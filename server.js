const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

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
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({ model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.3, max_tokens: 2048 })
    });
    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || "Groq API error" });
    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
    res.json(JSON.parse(clean));
  } catch (err) {
    res.status(500).json({ error: "Failed to generate notes. Please try again." });
  }
});

app.post("/api/create-order", async (req, res) => {
  const { plan } = req.body;
  const amount = plan === "annual" ? 69900 : 9900;
  try {
    const response = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Basic " + Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64")
      },
      body: JSON.stringify({ amount, currency: "INR", receipt: `receipt_${Date.now()}` })
    });
    const order = await response.json();
    if (!response.ok) return res.status(500).json({ error: order.error?.description || "Order creation failed" });
    res.json({ orderId: order.id, amount, currency: "INR", keyId: RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ error: "Failed to create payment order" });
  }
});

app.post("/api/verify-payment", (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const expectedSignature = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(razorpay_order_id + "|" + razorpay_payment_id)
    .digest("hex");
  if (expectedSignature === razorpay_signature) {
    res.json({ success: true, paymentId: razorpay_payment_id });
  } else {
    res.status(400).json({ success: false, error: "Payment verification failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StudySnap running on port ${PORT}`));
