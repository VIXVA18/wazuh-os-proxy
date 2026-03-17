import express from "express";
import axios from "axios";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

const PROXY = process.env.EC2_PROXY || "http://3.108.234.45:4000";

app.get("/health", async (_req, res) => {
  try {
    const r = await axios.get(`${PROXY}/health`);
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ status: "error", message: e.message });
  }
});

app.get("/alerts/stats", async (req, res) => {
  try {
    const r = await axios.get(`${PROXY}/alerts/stats`, { params: req.query });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts", async (req, res) => {
  try {
    const r = await axios.get(`${PROXY}/alerts`, { params: req.query });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts/agent/:name", async (req, res) => {
  try {
    const r = await axios.get(`${PROXY}/alerts/agent/${req.params.name}`, { params: req.query });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts/mitre", async (req, res) => {
  try {
    const r = await axios.get(`${PROXY}/alerts/mitre`, { params: req.query });
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/agents/status", async (_req, res) => {
  try {
    const r = await axios.get(`${PROXY}/agents/status`);
    res.json(r.data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Forwarder running on ${PORT} → ${PROXY}`));
