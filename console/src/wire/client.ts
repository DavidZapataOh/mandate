import { parseHello, parseLine } from "./parse";
import type { ConsoleLine, Hello } from "./types";

export type StreamState = "live" | "reconnecting";

export interface EventSourceLike {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent<string>) => void) | null;
  onerror: ((event: Event) => void) | null;
  addEventListener(type: "hello", listener: (event: MessageEvent<string>) => void): void;
  close(): void;
}

export const RETRY_MS = 1000;

const CLOSED = 2;

export interface LiveOptions {
  onLine(line: ConsoleLine): void;
  onState(state: StreamState): void;
  onReset(): void;
  onHello?(hello: Hello): void;
  onReject?(text: string, error: unknown): void;
  open?: (url: string) => EventSourceLike;
  schedule?: (run: () => void, ms: number) => void;
}

/** Follow the live event stream, resuming after the last line seen. */
export function connectLive(options: LiveOptions): { close(): void } {
  const open: (url: string) => EventSourceLike =
    options.open ?? ((url: string) => new EventSource(url));
  const schedule = options.schedule ?? ((run: () => void, ms: number) => void setTimeout(run, ms));
  let last = 0;
  let epoch: string | null = null;
  let stopped = false;
  let reopening = false;
  let source: EventSourceLike;

  const connect = (): void => {
    const current = open(`/api/events?since=${last}`);
    source = current;
    const stale = (): boolean => source !== current || stopped;
    current.onopen = () => {
      if (!stale()) options.onState("live");
    };
    current.onmessage = (event) => {
      if (stale()) return;
      let line: ConsoleLine;
      try {
        line = parseLine(event.data);
      } catch (error) {
        options.onReject?.(event.data, error);
        return;
      }
      last = Math.max(last, line.seq);
      try {
        options.onLine(line);
      } catch (error) {
        queueMicrotask(() => {
          throw error;
        });
      }
    };
    current.addEventListener("hello", (event) => {
      if (stale()) return;
      try {
        const hello = parseHello(event.data);
        if (epoch !== null && hello.epoch !== epoch) {
          epoch = hello.epoch;
          last = 0;
          options.onReset();
          current.close();
          connect();
          return;
        }
        epoch = hello.epoch;
        options.onHello?.(hello);
      } catch (error) {
        options.onReject?.(event.data, error);
      }
    });
    current.onerror = () => {
      if (stale()) return;
      options.onState("reconnecting");
      if (current.readyState !== CLOSED || reopening) return;
      reopening = true;
      current.close();
      schedule(() => {
        if (stopped || !reopening) return;
        reopening = false;
        connect();
      }, RETRY_MS);
    };
  };

  connect();
  return {
    close() {
      stopped = true;
      reopening = false;
      source.close();
    },
  };
}
