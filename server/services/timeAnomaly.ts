export interface TimeAnomalyResult {
  score: number;
  findings: string[];
  sendHour: number | null;
  sendDay: string | null;
  anomalyType: string;
}

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

export function detectTimeAnomaly(dateHeader: string): TimeAnomalyResult {
  const result: TimeAnomalyResult = {
    score: 0,
    findings: [],
    sendHour: null,
    sendDay: null,
    anomalyType: "",
  };

  if (!dateHeader) return result;

  const parsed = new Date(dateHeader);
  if (isNaN(parsed.getTime())) return result;

  const hour = parsed.getUTCHours();
  const day = parsed.getUTCDay();

  result.sendHour = hour;
  result.sendDay = DAYS[day];

  if (hour >= 1 && hour <= 5) {
    result.score = 8;
    result.anomalyType = "unusual-hour";
    result.findings.push(
      `This email was sent at ${hour}:00 UTC, which is an unusual time for legitimate business communication. Phishing campaigns often operate outside normal hours.`
    );
  }

  if ((day === 0 || day === 6) && (hour >= 0 && hour <= 6)) {
    result.score = Math.max(result.score, 10);
    result.anomalyType = "weekend-night";
    result.findings = [
      `This email was sent on a ${DAYS[day]} at ${hour}:00 UTC. Weekend late-night emails requesting urgent action are a common phishing pattern.`
    ];
  }

  return result;
}

export function extractDateFromHeaders(rawHeaders: string): string {
  const match = rawHeaders.match(/^Date:\s*(.+?)(?=\n[^\s]|$)/im);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}
