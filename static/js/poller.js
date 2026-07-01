export class Poller {
  constructor(interval, task, onError = () => {}) {
    this.interval = interval;
    this.task = task;
    this.onError = onError;
    this.timer = null;
    this.controller = null;
    this.stopped = true;
    this.visibilityHandler = () => {
      if (document.hidden) this.abort();
      else if (!this.stopped) this.run();
    };
  }

  start(immediate = true) {
    this.stopped = false;
    document.addEventListener("visibilitychange", this.visibilityHandler);
    if (immediate) this.run();
    else this.schedule();
    return this;
  }

  async run() {
    clearTimeout(this.timer);
    if (this.stopped || document.hidden) return;
    this.abort();
    this.controller = new AbortController();
    try {
      await this.task(this.controller.signal);
    } catch (error) {
      if (error.name !== "AbortError") this.onError(error);
    } finally {
      this.controller = null;
      this.schedule();
    }
  }

  schedule() {
    clearTimeout(this.timer);
    if (!this.stopped) this.timer = setTimeout(() => this.run(), this.interval);
  }

  abort() {
    if (this.controller) this.controller.abort();
    this.controller = null;
  }

  stop() {
    this.stopped = true;
    clearTimeout(this.timer);
    this.abort();
    document.removeEventListener("visibilitychange", this.visibilityHandler);
  }
}
