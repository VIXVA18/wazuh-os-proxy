 import express from "express";
import axios from "axios";
import https from "https";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || "*" }));

const OS_HOST = process.env.OPENSEARCH_HOST || "https://localhost";
const OS_PORT = process.env.OPENSEARCH_PORT || "9200";
const OS_USER = process.env.OPENSEARCH_USER || "admin";
const OS_PASS = process.env.OPENSEARCH_PASS || "admin";
const PORT    = process.env.PORT || "4000";
const INDEX   = "wazuh-alerts-4.x-*";
const BASE    = `${OS_HOST}:${OS_PORT}`;

const agent = new https.Agent({ rejectUnauthorized: false });
const auth  = { username: OS_USER, password: OS_PASS };

async function osSearch(body, index = INDEX) {
  const res = await axios.post(`${BASE}/${index}/_search`, body, {
    auth, httpsAgent: agent,
    headers: { "Content-Type": "application/json" },
  });
  return res.data;
}

function timeRange(hours = 24) {
  return { range: { timestamp: { gte: `now-${hours}h`, lte: "now" } } };
}

app.get("/health", async (_req, res) => {
  try {
    const r = await axios.get(`${BASE}/_cluster/health`, { auth, httpsAgent: agent });
    res.json({ status: "ok", cluster: r.data });
  } catch (e) {
    res.status(500).json({ status: "error", message: e.message });
  }
});

app.get("/alerts/stats", async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  try {
    const data = await osSearch({
      size: 0,
      query: { bool: { must: [timeRange(hours)] } },
      aggs: {
        total: { value_count: { field: "rule.id" } },
        by_severity: {
          range: {
            field: "rule.level",
            ranges: [
              { key: "low",      from: 1,  to: 7  },
              { key: "medium",   from: 7,  to: 11 },
              { key: "high",     from: 11, to: 13 },
              { key: "critical", from: 13, to: 20 },
            ],
          },
        },
        top_agents:      { terms: { field: "agent.name",        size: 10, order: { _count: "desc" } } },
        top_rule_groups: { terms: { field: "rule.groups",       size: 10, order: { _count: "desc" } } },
        top_rules:       { terms: { field: "rule.description",  size: 10, order: { _count: "desc" } } },
        over_time: {
          date_histogram: {
            field: "timestamp",
            fixed_interval: hours <= 24 ? "1h" : hours <= 168 ? "6h" : "1d",
            min_doc_count: 0,
            extended_bounds: { min: `now-${hours}h`, max: "now" },
          },
        },
        mitre_tactics: { terms: { field: "rule.mitre.tactic", size: 10, missing: "unclassified" } },
      },
    });

    const aggs = data.aggregations;
    res.json({
      hours,
      total: aggs.total.value,
      by_severity:     aggs.by_severity.buckets.map(b => ({ severity: b.key, count: b.doc_count })),
      top_agents:      aggs.top_agents.buckets.map(b => ({ agent: b.key, count: b.doc_count })),
      top_rule_groups: aggs.top_rule_groups.buckets.map(b => ({ group: b.key, count: b.doc_count })),
      top_rules:       aggs.top_rules.buckets.map(b => ({ rule: b.key, count: b.doc_count })),
      over_time:       aggs.over_time.buckets.map(b => ({ time: b.key_as_string, count: b.doc_count })),
      mitre_tactics:   aggs.mitre_tactics.buckets.map(b => ({ tactic: b.key, count: b.doc_count })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts", async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  const level = parseInt(req.query.level) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const agentFilter = req.query.agent || null;
  const group = req.query.group || null;

  const must = [timeRange(hours), { range: { "rule.level": { gte: level } } }];
  if (agentFilter) must.push({ match: { "agent.name": agentFilter } });
  if (group) must.push({ match: { "rule.groups": group } });

  try {
    const data = await osSearch({
      size: limit,
      sort: [{ timestamp: { order: "desc" } }],
      query: { bool: { must } },
      _source: [
        "timestamp", "agent.id", "agent.name", "agent.ip",
        "rule.id", "rule.level", "rule.description", "rule.groups",
        "rule.mitre.id", "rule.mitre.tactic", "data.srcip", "data.dstip", "location",
      ],
    });

    const hits = data.hits.hits.map(h => ({
      timestamp:    h._source.timestamp,
      agent_id:     h._source.agent?.id,
      agent_name:   h._source.agent?.name,
      agent_ip:     h._source.agent?.ip,
      rule_id:      h._source.rule?.id,
      rule_level:   h._source.rule?.level,
      severity:     levelToSeverity(h._source.rule?.level),
      description:  h._source.rule?.description,
      groups:       h._source.rule?.groups,
      mitre_id:     h._source.rule?.mitre?.id,
      mitre_tactic: h._source.rule?.mitre?.tactic,
      src_ip:       h._source.data?.srcip,
      dst_ip:       h._source.data?.dstip,
      location:     h._source.location,
    }));

    res.json({ total: data.hits.total.value, returned: hits.length, hours, alerts: hits });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts/agent/:name", async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  const limit = parseInt(req.query.limit) || 20;
  try {
    const data = await osSearch({
      size: limit,
      sort: [{ timestamp: { order: "desc" } }],
      query: { bool: { must: [timeRange(hours), { match: { "agent.name": req.params.name } }] } },
      _source: ["timestamp", "agent.name", "rule.level", "rule.description", "rule.groups", "rule.mitre.tactic", "data.srcip", "location"],
    });
    res.json({ agent: req.params.name, total: data.hits.total.value, alerts: data.hits.hits.map(h => h._source) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/alerts/mitre", async (req, res) => {
  const hours = parseInt(req.query.hours) || 24;
  try {
    const data = await osSearch({
      size: 0,
      query: { bool: { must: [timeRange(hours)] } },
      aggs: {
        tactics: {
          terms: { field: "rule.mitre.tactic", size: 20, missing: "unclassified" },
          aggs: { techniques: { terms: { field: "rule.mitre.id", size: 10 } } },
        },
      },
    });
    res.json({
      hours,
      tactics: data.aggregations.tactics.buckets.map(t => ({
        tactic: t.key, count: t.doc_count,
        techniques: t.techniques.buckets.map(tech => ({ id: tech.key, count: tech.doc_count })),
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/agents/status", async (_req, res) => {
  const WAZUH_HOST = process.env.WAZUH_HOST;
  const WAZUH_PORT = process.env.WAZUH_PORT || "55000";
  const WAZUH_USER = process.env.WAZUH_USER;
  const WAZUH_PASS = process.env.WAZUH_PASS;

  if (!WAZUH_HOST || !WAZUH_USER) {
    return res.json({ note: "Wazuh API not configured" });
  }
  try {
    const authRes = await axios.post(`${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate`, null,
      { auth: { username: WAZUH_USER, password: WAZUH_PASS }, httpsAgent: agent });
    const token = authRes.data.data.token;
    const headers = { Authorization: `Bearer ${token}` };
    const [active, disconnected, never, pending] = await Promise.all([
      axios.get(`${WAZUH_HOST}:${WAZUH_PORT}/agents`, { headers, httpsAgent: agent, params: { status: "active",         limit: 1 } }),
      axios.get(`${WAZUH_HOST}:${WAZUH_PORT}/agents`, { headers, httpsAgent: agent, params: { status: "disconnected",    limit: 1 } }),
      axios.get(`${WAZUH_HOST}:${WAZUH_PORT}/agents`, { headers, httpsAgent: agent, params: { status: "never_connected", limit: 1 } }),
      axios.get(`${WAZUH_HOST}:${WAZUH_PORT}/agents`, { headers, httpsAgent: agent, params: { status: "pending",         limit: 1 } }),
    ]);
    res.json({
      active:          active.data.data.total_affected_items,
      disconnected:    disconnected.data.data.total_affected_items,
      never_connected: never.data.data.total_affected_items,
      pending:         pending.data.data.total_affected_items,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function levelToSeverity(level) {
  if (!level) return "unknown";
  if (level >= 13) return "critical";
  if (level >= 11) return "high";
  if (level >= 7)  return "medium";
  return "low";
}

app.listen(PORT, () => {
  console.log(`Wazuh OpenSearch proxy running on http://localhost:${PORT}`);
  console.log(`OpenSearch: ${BASE}`);
});