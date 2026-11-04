//! Notary, prover and verifier for balance proofs over a bank's HTTPS API.

use std::{
    env,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::Empty;
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, Record, TranscriptCommitConfig},
    verifier::VerifierOutput,
    webpki::RootCertStore,
    Session,
};
use tlsn_formats::{
    http::{BodyContent, HttpTranscript},
    json::JsonValue,
    spansy::Spanned,
};

const MAX_SENT: usize = 1024;
const MAX_RECV: usize = 4096;
const MAX_FRAME: u32 = 1 << 20;
const SENT_HEADERS: [&str; 5] = ["host", "accept", "accept-encoding", "connection", "mandate-nonce"];
const MAX_SESSIONS: usize = 4;

#[derive(Parser)]
#[command(name = "mandate-zktls")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve notarizations; the key file holds 64 hex chars (secp256k1).
    Notary {
        #[arg(long)]
        listen: String,
        #[arg(long)]
        key_file: String,
        /// Exit when stdin reaches end of file (the parent died or let go).
        #[arg(long)]
        exit_on_stdin_eof: bool,
    },
    /// Prove one GET and write a presentation that reveals only the plan.
    Prove {
        #[arg(long)]
        notary: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        nonce: String,
        #[arg(long, value_delimiter = ',')]
        reveal: Vec<String>,
        #[arg(long)]
        auth_env: Option<String>,
        #[arg(long)]
        out: String,
    },
    /// Verify a presentation with Mozilla roots; print JSON.
    Verify {
        #[arg(long)]
        presentation: String,
    },
}

#[tokio::main]
async fn main() {
    let result = match Cli::parse().cmd {
        Cmd::Notary {
            listen,
            key_file,
            exit_on_stdin_eof,
        } => notary(listen, key_file, exit_on_stdin_eof).await,
        Cmd::Prove {
            notary,
            host,
            path,
            nonce,
            reveal,
            auth_env,
            out,
        } => prove(notary, host, path, nonce, reveal, auth_env, out).await,
        Cmd::Verify { presentation } => verify(presentation),
    };
    if let Err(err) = result {
        println!("{}", serde_json::json!({"ok": false, "error": format!("{err:#}")}));
        std::process::exit(1);
    }
}

/// The ranges a presentation reveals: everything a verifier must read, and
/// nothing else (never the Authorization value, never unlisted body fields).
#[derive(Debug, Default, PartialEq)]
struct Plan {
    sent: Vec<std::ops::Range<usize>>,
    recv: Vec<std::ops::Range<usize>>,
}

// Collects a span's index set; `RangeSet` is not re-exported by `tlsn`.
macro_rules! ranges {
    ($set:expr) => {
        $set.iter().collect::<Vec<std::ops::Range<usize>>>()
    };
}

fn reveal_plan(http: &HttpTranscript, fields: &[String]) -> Result<Plan> {
    let mut plan = Plan::default();
    let [req] = http.requests.as_slice() else {
        bail!("expected exactly one request");
    };
    let [resp] = http.responses.as_slice() else {
        bail!("expected exactly one response");
    };
    plan.sent.extend(ranges!(req.without_data()));
    plan.sent.extend(ranges!(req.request.target.span().indices()));
    for header in &req.headers {
        let name = header.name.as_str().to_ascii_lowercase();
        if SENT_HEADERS.contains(&name.as_str()) {
            plan.sent.extend(ranges!(header.span().indices()));
        } else {
            plan.sent.extend(ranges!(header.without_value()));
        }
    }
    // The whole response head is revealed so a verifier can check that the
    // content-length accounts for every received byte: one response only.
    plan.recv.extend(ranges!(resp.without_data()));
    for header in &resp.headers {
        plan.recv.extend(ranges!(header.span().indices()));
    }
    let body = resp.body.as_ref().context("response has no body")?;
    let BodyContent::Json(JsonValue::Object(object)) = &body.content else {
        bail!("response body is not a JSON object");
    };
    for field in fields {
        let pair = object
            .elems
            .iter()
            .find(|kv| kv.key == field.as_str())
            .with_context(|| format!("response has no field {field}"))?;
        plan.recv.extend(ranges!(pair.span().indices()));
    }
    Ok(plan)
}

async fn write_frame(io: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    io.write_u32(u32::try_from(bytes.len())?).await?;
    io.write_all(bytes).await?;
    Ok(())
}

async fn read_frame(io: &mut TcpStream) -> Result<Vec<u8>> {
    let len = io.read_u32().await?;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

fn notary_provider(key_hex: &str) -> Result<(CryptoProvider, String)> {
    let raw = hex::decode(key_hex.trim()).context("key file is not hex")?;
    let raw: [u8; 32] = raw.try_into().map_err(|_| anyhow!("key must be 32 bytes"))?;
    let signing = k256::ecdsa::SigningKey::from_bytes(&raw.into())?;
    let public = hex::encode(signing.verifying_key().to_encoded_point(true).as_bytes());
    let mut provider = CryptoProvider::default();
    provider
        .signer
        .set_signer(Box::new(Secp256k1Signer::new(&raw)?));
    Ok((provider, public))
}

async fn notary(listen: String, key_file: String, exit_on_stdin_eof: bool) -> Result<()> {
    let key_hex = std::fs::read_to_string(&key_file)?;
    let (_, public) = notary_provider(&key_hex)?;
    let listener = TcpListener::bind(&listen).await?;
    println!(
        "{}",
        serde_json::json!({"listening": listener.local_addr()?.to_string(), "notary_key": public})
    );
    if exit_on_stdin_eof {
        tokio::spawn(async {
            let mut sink = Vec::new();
            let _ = tokio::io::stdin().read_to_end(&mut sink).await;
            std::process::exit(0);
        });
    }
    let sessions = Arc::new(Semaphore::new(MAX_SESSIONS));
    loop {
        let socket = match listener.accept().await {
            Ok((socket, _)) => socket,
            Err(err) => {
                // e.g. EMFILE: keep serving once descriptors free up.
                eprintln!("accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            eprintln!("notarization refused: {MAX_SESSIONS} sessions running");
            continue;
        };
        let key_hex = key_hex.clone();
        tokio::spawn(async move {
            if let Err(err) = notarize(socket, &key_hex).await {
                eprintln!("notarization failed: {err:#}");
            }
            drop(permit);
        });
    }
}

fn app_data_len(records: &[Record]) -> u32 {
    records
        .iter()
        .filter(|r| matches!(r.typ, ContentType::ApplicationData))
        .map(|r| r.ciphertext.len())
        .sum::<usize>() as u32
}

async fn notarize(socket: TcpStream, key_hex: &str) -> Result<()> {
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let driver_task = tokio::spawn(driver);
    let config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;
    let verifier = handle
        .new_verifier(config)?
        .commit()
        .await?
        .accept()
        .await?
        .run()
        .await?;
    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;
    let tls = verifier.tls_transcript().clone();
    verifier.close().await?;
    handle.close();
    let mut io = driver_task.await??.into_inner();
    let request: AttestationRequest = bincode::deserialize(&read_frame(&mut io).await?)?;
    let (provider, _) = notary_provider(key_hex)?;
    let mut config = AttestationConfig::builder();
    config.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let config = config.build()?;
    let mut builder = Attestation::builder(&config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls.time(),
            version: *tls.version(),
            transcript_length: TranscriptLength {
                sent: app_data_len(tls.sent()),
                received: app_data_len(tls.recv()),
            },
        })
        .server_ephemeral_key(tls.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);
    let attestation = builder.build(&provider)?;
    write_frame(&mut io, &bincode::serialize(&attestation)?).await?;
    Ok(())
}

async fn prove(
    notary: String,
    host: String,
    path: String,
    nonce: String,
    reveal: Vec<String>,
    auth_env: Option<String>,
    out: String,
) -> Result<()> {
    let started = Instant::now();
    let notary_socket = TcpStream::connect(&notary).await?;
    let (driver, mut handle) = Session::new(notary_socket.compat()).split();
    let driver_task = tokio::spawn(driver);
    let mpc = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        .build()?;
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(TlsCommitConfig::builder().protocol(mpc).build()?)
        .await?;
    let server = TcpStream::connect((host.as_str(), 443)).await?;
    let tls_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(host.clone().try_into()?))
        .root_store(RootCertStore::mozilla())
        .build()?;
    let (tls, prover_fut) = prover.connect(tls_config, server.compat()).await?;
    let prover_task = tokio::spawn(prover_fut);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls.compat())).await?;
    tokio::spawn(conn);
    let mut request = Request::builder()
        .uri(path)
        .header("Host", host.as_str())
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("Mandate-Nonce", nonce.as_str());
    if let Some(name) = auth_env {
        let token = env::var(&name).with_context(|| format!("{name} is not set"))?;
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = sender
        .send_request(request.body(Empty::<Bytes>::new())?)
        .await?;
    let status = response.status().as_u16();
    let mut prover = prover_task.await??;

    let http = HttpTranscript::parse(prover.transcript())?;
    let plan = reveal_plan(&http, &reveal)?;
    let mut commit = TranscriptCommitConfig::builder(prover.transcript());
    for range in &plan.sent {
        commit.commit_sent(range)?;
    }
    for range in &plan.recv {
        commit.commit_recv(range)?;
    }
    let mut request_config = RequestConfig::builder();
    request_config.transcript_commit(commit.build()?);
    let request_config = request_config.build()?;
    let mut prove_config = ProveConfig::builder(prover.transcript());
    if let Some(config) = request_config.transcript_commit() {
        prove_config.transcript_commit(config.clone());
    }
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config.build()?).await?;
    let transcript = prover.transcript().clone();
    let tls = prover.tls_transcript().clone();
    prover.close().await?;
    handle.close();
    let mut io = driver_task.await??.into_inner();

    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(host.clone().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls.server_cert_chain().context("no certificate chain")?.to_vec(),
            sig: tls.server_signature().context("no server signature")?.clone(),
            binding: tls.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let provider = CryptoProvider::default();
    let (attestation_request, secrets) = builder.build(&provider)?;
    write_frame(&mut io, &bincode::serialize(&attestation_request)?).await?;
    let attestation: Attestation = bincode::deserialize(&read_frame(&mut io).await?)?;
    attestation_request.validate(&attestation, &provider)?;

    let mut proof = secrets.transcript_proof_builder();
    for range in &plan.sent {
        proof.reveal_sent(range)?;
    }
    for range in &plan.recv {
        proof.reveal_recv(range)?;
    }
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(proof.build()?);
    let presentation: Presentation = presentation.build()?;
    let bytes = bincode::serialize(&presentation)?;
    std::fs::write(&out, &bytes)?;
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "status": status,
            "bytes": bytes.len(),
            "elapsed_ms": started.elapsed().as_millis() as u64,
        })
    );
    Ok(())
}

fn verify(path: String) -> Result<()> {
    let presentation: Presentation = bincode::deserialize(&std::fs::read(path)?)?;
    let key = hex::encode(&presentation.verifying_key().data);
    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;
    let mut transcript = transcript.context("presentation reveals no transcript")?;
    transcript.set_unauthed(0);
    let text = |bytes: &[u8]| String::from_utf8(bytes.to_vec()).context("transcript is not UTF-8");
    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "server_name": server_name.context("no server name")?.to_string(),
            "time": connection_info.time,
            "notary_key": key,
            "sent": text(transcript.sent_unsafe())?,
            "recv": text(transcript.received_unsafe())?,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlsn::transcript::Transcript;

    const SENT: &str = "GET /accounts/account_abc/balance HTTP/1.1\r\nhost: sandbox.increase.com\r\naccept: application/json\r\naccept-encoding: identity\r\nconnection: close\r\nmandate-nonce: n1\r\nauthorization: Bearer secret-key\r\n\r\n";
    const RECV: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-request-id: r1\r\ncontent-length: 114\r\n\r\n{\"account_id\":\"account_abc\",\"available_balance\":50000,\"current_balance\":50000,\"loan\":null,\"type\":\"balance_lookup\"}";

    fn revealed(text: &str, plan: &[std::ops::Range<usize>]) -> String {
        let mut out = vec![b'X'; text.len()];
        for r in plan {
            out[r.clone()].copy_from_slice(&text.as_bytes()[r.clone()]);
        }
        String::from_utf8(out).unwrap()
    }

    fn http(recv: &str) -> HttpTranscript {
        HttpTranscript::parse(&Transcript::new(SENT.as_bytes(), recv.as_bytes())).unwrap()
    }

    #[test]
    fn plan_hides_the_key_and_unlisted_fields() {
        let fields = vec!["account_id".to_string(), "available_balance".to_string()];
        let plan = reveal_plan(&http(RECV), &fields).unwrap();
        let sent = revealed(SENT, &plan.sent);
        let recv = revealed(RECV, &plan.recv);
        assert!(sent.starts_with("GET /accounts/account_abc/balance HTTP/1.1\r\n"));
        assert!(sent.contains("mandate-nonce: n1\r\n"));
        assert!(!sent.contains("secret-key"));
        assert!(sent.contains("authorization: "));
        assert!(recv.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(recv.contains("\"available_balance\":50000"));
        assert!(recv.contains("\"account_id\":\"account_abc\""));
        assert!(!recv.contains("current_balance"));
        let head = RECV.find("\r\n\r\n").unwrap() + 4;
        assert_eq!(&recv[..head], &RECV[..head], "every response header is revealed");
        assert_eq!(recv.len(), RECV.len());
        let hidden = sent.bytes().filter(|b| *b == b'X').count();
        assert_eq!(hidden, "Bearer secret-key".len(), "only the key value is hidden");
    }

    #[test]
    fn plan_refuses_a_missing_field() {
        let fields = vec!["available_balance".to_string(), "missing".to_string()];
        let err = reveal_plan(&http(RECV), &fields).unwrap_err();
        assert_eq!(err.to_string(), "response has no field missing");
    }

    #[test]
    fn plan_refuses_a_body_that_is_not_an_object() {
        let recv = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n[]";
        let err = reveal_plan(&http(recv), &["type".to_string()]).unwrap_err();
        assert_eq!(err.to_string(), "response body is not a JSON object");
    }
}
