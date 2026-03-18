const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

app.post("/api/generate", async (req, res) => {
  const { topic, level, depth } = req.body;
  if (!topic) return res.status(400).json({ error: "Topic is required" });

  const numPoints = depth === "quick" ? 5 : depth === "deep" ? 15 : 10;

  const prompt = `You are an expert study assistant and educator. Generate accurate, detailed study notes for the topic: "${topic}" at ${level || "intermediate"} level.
You MUST respond with ONLY valid JSON — no markdown fences, no explanation, no extra text before or after.
Use this exact JSON structure:
{"definition":"2-3 sentence overview","points":[{"title":"Concept","text":"Explanation with <strong>key terms</strong>"}],"formulas":["formula if applicable"],"qa":[{"q":"Question?","a":"Answer.","diff":"easy"}]}
Rules: ${numPoints} points, 5 qa items, diff = easy/medium/hard, empty formulas array if none, use <strong> tags`;

  try {
    const response = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: "llama3-70b-8192",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.3,
        max_tokens: 2048
      })
    });

    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || "Groq API error" });

    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
    const parsed = JSON.parse(clean);
    res.json(parsed);
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Failed to generate notes. Please try again." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StudySnap running on port ${PORT}`));
