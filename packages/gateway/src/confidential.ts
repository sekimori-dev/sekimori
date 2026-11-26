import { randomBytes } from "node:crypto";

// What a cloud model may read; see docs/superpowers/specs/2026-11-25-confidential-data-design.md.

export type Mode = "withhold" | "pseudonymise";
type Pattern = { re: RegExp; valid?: (match: string) => boolean };
export type Origin = { class: string; source?: string };
export type Counts = Record<string, { withheld: number; pseudonymised: number; revealed: number }>;
export type Reveal = Origin & { placeholder?: string };

export interface DataClass {
  name: string;
  mode: Mode;
  fields: string[][];
  patterns: Pattern[];
  sources: RegExp[];
}

export interface ClassConfig {
  enabled?: boolean;
  mode?: Mode;
  fields?: string[];
  patterns?: string[];
  sources?: string[];
}

const digitsOf = (s: string) => s.replace(/\D/g, "");

function ibanValid(match: string): boolean {
  const iban = match.replace(/\s/g, "").toUpperCase();
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const value = char >= "A" ? char.charCodeAt(0) - 55 : Number(char);
    for (const digit of String(value)) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

function luhnValid(match: string): boolean {
  const digits = digitsOf(match);
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  }
  return sum % 10 === 0;
}

// German Steuer-Identifikationsnummer: ISO 7064 MOD 11,10.
function deTaxIdValid(match: string): boolean {
  const digits = digitsOf(match);
  if (digits.length !== 11 || digits[0] === "0") return false;
  let product = 10;
  for (const char of digits.slice(0, 10)) {
    let sum = (Number(char) + product) % 10;
    if (sum === 0) sum = 10;
    product = (sum * 2) % 11;
  }
  return (11 - product) % 10 === Number(digits[10]);
}

// Austrian Sozialversicherungsnummer: the fourth digit checks the others.
function atSvnrValid(match: string): boolean {
  const digits = digitsOf(match);
  if (digits.length !== 10) return false;
  const weights = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];
  const check = [...digits].reduce((sum, d, i) => sum + Number(d) * weights[i]!, 0) % 11;
  return check !== 10 && check === Number(digits[3]);
}

const p = (source: string, valid?: (m: string) => boolean): Pattern => ({ re: new RegExp(source, "g"), valid });

const CATALOGUE: Record<string, { enabled: boolean; mode: Mode; fields: string[]; patterns: Pattern[] }> = {
  credentials: {
    enabled: true,
    mode: "withhold",
    fields: ["password", "secret", "token", "api_key", "private_key"],
    patterns: [
      p(String.raw`\bsk-[A-Za-z0-9_-]{20,}`),
      p(String.raw`\bgh[pousr]_[A-Za-z0-9]{30,}`),
      p(String.raw`\bgithub_pat_[A-Za-z0-9_]{20,}`),
      p(String.raw`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
      p(String.raw`\bAKIA[0-9A-Z]{16}\b`),
      p(String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
      p(String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
    ],
  },
  bank: {
    enabled: true,
    mode: "pseudonymise",
    fields: ["iban", "bic", "account_number", "kontonummer"],
    patterns: [p(String.raw`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`, ibanValid), p(String.raw`\b(?:\d[ -]?){12,18}\d\b`, luhnValid)],
  },
  national_id: {
    enabled: true,
    mode: "pseudonymise",
    fields: ["tax_id", "steuer_id", "ssn", "svnr", "sozialversicherungsnummer", "vat_id", "uid"],
    patterns: [
      p(String.raw`\b\d{11}\b`, deTaxIdValid),
      p(String.raw`\b\d{4} ?\d{6}\b`, atSvnrValid),
      p(String.raw`\b(?:ATU\d{8}|DE\d{9}|(?:BE|BG|CY|CZ|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Z]{8,12})\b`),
    ],
  },
  payroll: {
    enabled: true,
    mode: "withhold",
    fields: ["salary", "gross_pay", "net_pay", "wage", "bonus", "compensation", "gehalt", "lohn", "brutto", "netto"],
    patterns: [],
  },
  health: {
    enabled: true,
    mode: "withhold",
    fields: ["diagnosis", "icd", "illness", "sick_leave", "diagnose", "krankheit", "krankenstand"],
    patterns: [],
  },
  contact: {
    enabled: false,
    mode: "pseudonymise",
    fields: ["email", "phone", "mobile", "address", "telefon", "adresse"],
    patterns: [p(String.raw`[\w.+-]+@[\w-]+(?:\.[\w-]+)+`), p(String.raw`\+\d[\d ()/-]{7,}\d`)],
  },
  person: {
    enabled: false,
    mode: "pseudonymise",
    fields: ["first_name", "last_name", "full_name", "birth_date", "vorname", "nachname", "geburtsdatum"],
    patterns: [],
  },
};

const words = (s: string) =>
  s
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);

const glob = (pattern: string) => new RegExp(`^${pattern.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);

export function resolveClasses(config: Record<string, ClassConfig> = {}): DataClass[] {
  const names = new Set([...Object.keys(CATALOGUE), ...Object.keys(config)]);
  return [...names].flatMap((name) => {
    const base = CATALOGUE[name];
    const own = config[name] ?? {};
    if (!(own.enabled ?? base?.enabled ?? true)) return [];
    return [
      {
        name,
        mode: own.mode ?? base?.mode ?? "withhold",
        fields: [...(base?.fields ?? []), ...(own.fields ?? [])].map(words),
        patterns: [...(base?.patterns ?? []), ...(own.patterns ?? []).map((source) => p(source))],
        sources: (own.sources ?? []).map(glob),
      },
    ];
  });
}

const PLACEHOLDER = /⟦([a-z][\w-]*)·([0-9a-f]{6})⟧/g;
const NUMBER_TOKEN = /\d{1,3}(?:[.,' ]\d{3})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?/g;

// A number written in text may use either separator convention, so both readings are tried.
function readings(token: string): number[] {
  const plain = token.replace(/[' ]/g, "");
  return [Number(plain.replace(/,/g, "")), Number(plain.replace(/\./g, "").replace(",", "."))].filter(Number.isFinite);
}

// Forwarding compares values with spacing, separators and case removed, since programs reformat what they pass on.
const normal = (text: string) => text.toLowerCase().replace(/[\s.,'_/-]/g, "");

function parseJson(text: string): unknown {
  const trimmed = text.trim();
  if (!/^[[{]/.test(trimmed)) return undefined;
  try {
    // Unsafe integers lose digits as numbers; their exact source digits are kept as strings for the pattern checks.
    return JSON.parse(trimmed, (_key, value, context?: { source?: string }) =>
      typeof value === "number" && !Number.isSafeInteger(value) && /^-?\d+$/.test(context?.source ?? "") ? context!.source : value,
    );
  } catch {
    return undefined;
  }
}

export type Confidential = ReturnType<typeof createConfidential>;

// One instance per gateway session: known values and the placeholder vault live as long as the session.
export function createConfidential(classes: DataClass[]) {
  const byName = new Map(classes.map((c) => [c.name, c]));
  const knownStrings = new Map<string, Origin>();
  const knownNumbers = new Map<number, Origin>();
  const vault = new Map<string, { value: string | number | boolean; origin: Origin }>();
  const placeholderOf = new Map<string, string>();

  const fieldClass = (key: string): string | undefined => {
    const keyWords = words(key);
    return classes.find((c) => c.fields.some((field) => keyWords.some((_, i) => field.every((w, j) => keyWords[i + j] === w))))?.name;
  };

  // Values too short to match safely elsewhere are still withheld under their field.
  function remember(value: unknown, origin: Origin): boolean {
    if (typeof value === "string" && value.length >= 4) {
      if (!knownStrings.has(value)) knownStrings.set(value, origin);
      // The sandbox sees digit strings from JSON as (possibly rounded) numbers, so remember that form too.
      if (/^-?\d+$/.test(value) && !knownNumbers.has(Number(value))) knownNumbers.set(Number(value), origin);
      return true;
    }
    if (typeof value === "number" && digitsOf(String(value)).length >= 4) {
      if (!knownNumbers.has(value)) knownNumbers.set(value, origin);
      return true;
    }
    return false;
  }

  function patternMatches(text: string): Array<{ match: string; class: string }> {
    const found: Array<{ match: string; class: string }> = [];
    for (const c of classes) {
      for (const { re, valid } of c.patterns) {
        for (const m of text.matchAll(re)) if (!valid || valid(m[0])) found.push({ match: m[0], class: c.name });
      }
    }
    return found;
  }

  function bump(counts: Counts, name: string, kind: keyof Counts[string]) {
    counts[name] ??= { withheld: 0, pseudonymised: 0, revealed: 0 };
    counts[name][kind]++;
  }

  function token(value: string | number | boolean, origin: Origin, counts: Counts): string {
    if (byName.get(origin.class)?.mode !== "pseudonymise") {
      bump(counts, origin.class, "withheld");
      return `⟦withheld:${origin.class}⟧`;
    }
    bump(counts, origin.class, "pseudonymised");
    const key = `${typeof value}:${value}`;
    let placeholder = placeholderOf.get(key);
    if (!placeholder) {
      placeholder = `⟦${origin.class}·${randomBytes(3).toString("hex")}⟧`;
      placeholderOf.set(key, placeholder);
      vault.set(placeholder, { value, origin });
    }
    return placeholder;
  }

  function scrubText(text: string, counts: Counts): string {
    let out = text;
    // Patterns can overlap (a card number inside an IBAN); only what is still in the text gets replaced.
    for (const { match, class: name } of patternMatches(out)) {
      if (out.includes(match)) out = out.split(match).join(token(match, knownStrings.get(match) ?? { class: name }, counts));
    }
    for (const [value, origin] of [...knownStrings].sort((a, b) => b[0].length - a[0].length)) {
      if (out.includes(value)) out = out.split(value).join(token(value, origin, counts));
    }
    if (knownNumbers.size > 0) {
      out = out.replace(NUMBER_TOKEN, (number) => {
        const hit = readings(number).find((n) => knownNumbers.has(n));
        return hit === undefined ? number : token(hit, knownNumbers.get(hit)!, counts);
      });
    }
    return out;
  }

  function scrub(value: unknown, counts: Counts): unknown {
    if (typeof value === "string") {
      // JSON passed on as text is checked as structure, so markers stay valid JSON for the model.
      const parsed = parseJson(value);
      return parsed === undefined ? scrubText(value, counts) : JSON.stringify(scrub(parsed, counts));
    }
    if (typeof value === "number") {
      if (knownNumbers.has(value)) return token(value, knownNumbers.get(value)!, counts);
      const pattern = patternMatches(String(value))[0];
      return pattern ? token(value, { class: pattern.class }, counts) : value;
    }
    if (Array.isArray(value)) return value.map((item) => scrub(item, counts));
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(value)) {
        let name = scrubText(key, counts);
        for (let n = 2; name in out; n++) name = `${scrubText(key, counts)} (${n})`;
        const field = fieldClass(key);
        // Under a confidential field only a computed number passes, so averages stay usable.
        const keep = !field || item === null || typeof item === "object" || (typeof item === "number" && !knownNumbers.has(item));
        out[name] = keep
          ? scrub(item, counts)
          : token(item as string | number | boolean, knownStrings.get(item as string) ?? { class: field }, counts);
      }
      return out;
    }
    return value;
  }

  return {
    // Step 1: records confidential values in a tool's answer; returns how many it found.
    inspect(source: string, result: unknown): number {
      let found = 0;
      const root = classes.find((c) => c.sources.some((re) => re.test(source)))?.name;
      const walk = (node: unknown, inherited: string | undefined) => {
        if (typeof node === "string") {
          const parsed = parseJson(node);
          if (parsed !== undefined) return walk(parsed, inherited);
          const lines = node.split("\n").map(parseJson).filter((l) => l !== undefined);
          if (lines.length > 0) return lines.forEach((line) => walk(line, inherited));
          if (inherited && remember(node, { class: inherited, source })) found++;
          for (const { match, class: name } of patternMatches(node)) if (remember(match, { class: name, source })) found++;
          return;
        }
        if (typeof node === "number" || typeof node === "boolean") {
          if (inherited && remember(node, { class: inherited, source })) found++;
          const pattern = typeof node === "number" ? patternMatches(String(node))[0] : undefined;
          if (pattern && remember(node, { class: pattern.class, source })) found++;
          return;
        }
        if (Array.isArray(node)) return node.forEach((item) => walk(item, inherited));
        if (node && typeof node === "object") {
          for (const [key, item] of Object.entries(node)) {
            for (const { match, class: name } of patternMatches(key)) if (remember(match, { class: name, source })) found++;
            walk(item, fieldClass(key) ?? inherited);
          }
        }
      };
      walk(result, root);
      return found + (root ? 1 : 0);
    },

    // Step 2: what the model receives instead of the program's value or error text.
    scrub: (value: unknown, counts: Counts) => scrub(value, counts),
    scrubText: (text: string, counts: Counts) => scrubText(text, counts),

    // Puts real values back for placeholders and lists every confidential value an outgoing call carries.
    outbound(args: unknown): { args: unknown; reveals: Reveal[] } {
      const reveals: Reveal[] = [];
      const note = (reveal: Reveal) => {
        if (!reveals.some((r) => r.class === reveal.class && r.source === reveal.source && r.placeholder === reveal.placeholder)) reveals.push(reveal);
      };
      const walk = (node: unknown): unknown => {
        if (typeof node === "string") {
          const whole = vault.get(node);
          if (whole) {
            note({ ...whole.origin, placeholder: node });
            return whole.value;
          }
          const flat = normal(node);
          for (const [value, origin] of knownStrings) if (normal(value).length >= 4 && flat.includes(normal(value))) note(origin);
          for (const number of node.match(NUMBER_TOKEN) ?? []) {
            const hit = readings(number).find((n) => knownNumbers.has(n));
            if (hit !== undefined) note(knownNumbers.get(hit)!);
          }
          return node.replace(PLACEHOLDER, (placeholder) => {
            const entry = vault.get(placeholder);
            if (!entry) return placeholder;
            note({ ...entry.origin, placeholder });
            return String(entry.value);
          });
        }
        if (typeof node === "number" && knownNumbers.has(node)) note(knownNumbers.get(node)!);
        if (Array.isArray(node)) return node.map(walk);
        if (node && typeof node === "object") return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, walk(v)]));
        return node;
      };
      return { args: walk(args), reveals };
    },

    // Placeholders written as literals in the code, known before the program runs.
    placeholdersIn(text: string): Reveal[] {
      return [...text.matchAll(PLACEHOLDER)].flatMap((m) => {
        const entry = vault.get(m[0]);
        return entry ? [{ ...entry.origin, placeholder: m[0] }] : [];
      });
    },

    isSource: (tool: string) => classes.some((c) => c.sources.some((re) => re.test(tool))),
    count: bump,

    describe(): string {
      if (classes.length === 0) return "";
      const list = classes.map((c) => `${c.name} (${c.mode === "withhold" ? "withheld" : "pseudonymised"})`).join(", ");
      return [
        `// Confidential data never reaches you raw. Active classes: ${list}.`,
        "// Tool results inside your program are complete: compute there and return only results, such as counts or averages.",
        "// ⟦withheld:class⟧ marks a removed value. ⟦class·id⟧ is a placeholder: pass it to tools and Sekimori inserts the real value",
        "// where policy allows. Placeholders never equal the real values inside your program, so you cannot look records up by them.",
      ].join("\n");
    },
  };
}
