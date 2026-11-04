import { encodeWav } from "./wav";
import type { Recorder } from "./widget";

const RATE = 16000;

interface Take {
  recorder: MediaRecorder;
  stream: MediaStream;
  chunks: Blob[];
}

/** The device microphone, each take returned as a 16 kHz mono WAV. */
export function micRecorder(media: MediaDevices = navigator.mediaDevices): Recorder {
  let take: Take | null = null;
  return {
    async start() {
      const stream = await media.getUserMedia({ audio: { channelCount: 1 } });
      const recorder = new MediaRecorder(stream);
      const chunks: Blob[] = [];
      recorder.addEventListener("dataavailable", (event) => {
        if (event.data.size > 0) chunks.push(event.data);
      });
      recorder.start();
      take = { recorder, stream, chunks };
    },
    async stop() {
      if (take === null) throw new Error("not recording");
      const { recorder, stream, chunks } = take;
      take = null;
      const stopped = new Promise((resolve) => recorder.addEventListener("stop", resolve, { once: true }));
      recorder.stop();
      await stopped;
      for (const track of stream.getTracks()) track.stop();
      const blob = new Blob(chunks, { type: recorder.mimeType });
      const context = new AudioContext();
      let audio: AudioBuffer;
      try {
        audio = await context.decodeAudioData(await blob.arrayBuffer());
      } finally {
        await context.close();
      }
      // The browser records at its own rate and codec; the desk reads 16 kHz PCM.
      const offline = new OfflineAudioContext(1, Math.max(1, Math.ceil(audio.duration * RATE)), RATE);
      const source = offline.createBufferSource();
      source.buffer = audio;
      source.connect(offline.destination);
      source.start();
      const rendered = await offline.startRendering();
      return encodeWav(rendered.getChannelData(0), RATE);
    },
  };
}
