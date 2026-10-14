export class RevisionDecoder {
  private pending = "";

  push(chunk: string): number[] {
    this.pending += chunk;
    const revisions: number[] = [];
    let match: RegExpExecArray | null;
    while ((match = /\r?\n\r?\n/.exec(this.pending))) {
      const frame = this.pending.slice(0, match.index);
      this.pending = this.pending.slice(match.index + match[0].length);
      const lines = frame.split(/\r?\n/);
      if (!lines.includes("event: update")) continue;
      const data = lines.filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n");
      if (/^\d+$/.test(data)) {
        const revision = Number(data);
        if (Number.isSafeInteger(revision)) revisions.push(revision);
      }
    }
    if (this.pending.length > 65536) throw new Error("Live frame exceeds limit");
    return revisions;
  }
}
