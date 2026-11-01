import { timingSafeEqual } from "node:crypto";

// In-memory storage. It lives only as long as the current function instance,
const submissions = [];

const ALLOWED = {
  strength: ["Very weak", "Weak", "Balanced", "Strong", "Very Strong"],
  taste: ["Very bitter", "Bitter", "Balanced", "Sweet", "Very Sweet"],
  temperature: ["Very Cold", "Cold", "Balanced", "Hot", "Very Hot"],
};

// Compares the key sent by the caller with the secret stored in Vercel.
function isValidKey(provided) {
  const expected = process.env.FORM_API_KEY;
  if (!expected || typeof provided !== "string") {
    return false;
  }

  const a = Buffer.from(provided);
  const b = Buffer.from(expected);

  // timingSafeEqual takes the same time whether the first or last character differs,
  // so an attacker can't guess the key character by character from response times.
  return a.length === b.length && timingSafeEqual(a, b);
}

// Returns a list of problems with the submission (empty list = valid).
function validate(body) {
  const errors = [];

  if (typeof body.submissionId !== "string" || body.submissionId === "") {
    errors.push("submissionId must be a non-empty string");
  }

  const rating = body.rating ?? null;
  if (
    rating !== null &&
    !(Number.isInteger(rating) && rating >= 1 && rating <= 5)
  ) {
    errors.push("rating must be a whole number from 1 to 5, or null");
  }

  for (const [field, options] of Object.entries(ALLOWED)) {
    const value = body[field] ?? null;
    if (value !== null && !options.includes(value)) {
      errors.push(`${field} must be one of: ${options.join(", ")}, or null`);
    }
  }

  return errors;
}

export default function handler(req, res) {
  // ---------- GET: return everything stored so far ----------
  if (req.method === "GET") {
    return res.status(200).json(submissions);
  }

  // ---------- POST: store a new submission ----------
  if (req.method === "POST") {
    // 1. Is the caller allowed to post? (Node lowercases all header names.)
    if (!isValidKey(req.headers["x-api-key"])) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // 2. Is the body a JSON object? Vercel has already parsed it into req.body.
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({ error: "Body must be a JSON object" });
    }

    // 3. Are the values ones we expect?
    const errors = validate(body);
    if (errors.length > 0) {
      return res
        .status(400)
        .json({ error: "Invalid submission", details: errors });
    }

    // 4. Have we already stored this exact submission?
    if (submissions.some((s) => s.submissionId === body.submissionId)) {
      return res.status(200).json({ ok: true, duplicate: true });
    }

    // 5. Build a clean object with only the fields we want, and store it.
    const entry = {
      submissionId: body.submissionId,
      submittedAt:
        typeof body.submittedAt === "string" ? body.submittedAt : null,
      receivedAt: new Date().toISOString(),
      rating: body.rating ?? null,
      strength: body.strength ?? null,
      taste: body.taste ?? null,
      temperature: body.temperature ?? null,
    };
    submissions.push(entry);

    return res.status(201).json({ ok: true, stored: entry });
  }

  // ---------- Any other method (PUT, DELETE...) ----------
  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ error: `Method ${req.method} not allowed` });
}
