import fs from "fs";
import path from "path";

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

export class Logger {
  private level: LogLevel;
  private logFilePath: string;

  constructor(level: LogLevel = LogLevel.INFO, logDir: string = "./logs") {
    this.level = level;
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    this.logFilePath = path.join(logDir, `forensic-audit-${timestamp}.log`);
  }

  private formatMessage(levelStr: string, message: string, meta?: any): string {
    const ts = new Date().toISOString();
    const metaStr = meta ? ` | Meta: ${JSON.stringify(meta)}` : "";
    return `[${ts}] [${levelStr}] ${message}${metaStr}`;
  }

  private writeToFile(msg: string) {
    fs.appendFileSync(this.logFilePath, msg + "\n");
  }

  public debug(message: string, meta?: any) {
    if (this.level <= LogLevel.DEBUG) {
      const formatted = this.formatMessage("DEBUG", message, meta);
      console.debug(formatted);
      this.writeToFile(formatted);
    }
  }

  public info(message: string, meta?: any) {
    if (this.level <= LogLevel.INFO) {
      const formatted = this.formatMessage("INFO", message, meta);
      console.info(formatted);
      this.writeToFile(formatted);
    }
  }

  public warn(message: string, meta?: any) {
    if (this.level <= LogLevel.WARN) {
      const formatted = this.formatMessage("WARN", message, meta);
      console.warn(formatted);
      this.writeToFile(formatted);
    }
  }

  public error(message: string, meta?: any) {
    if (this.level <= LogLevel.ERROR) {
      const formatted = this.formatMessage("ERROR", message, meta);
      console.error(formatted);
      this.writeToFile(formatted);
    }
  }
}

export const logger = new Logger();
