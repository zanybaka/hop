// Чистка образов репозитория в GHCR (.github/workflows/ghcr-cleanup.yml, раз в сутки и вручную).
// Остаются 10 последних образов с тегом, образы трёх последних production-выкаток из GitHub
// deployments, теги из PROTECT_TAGS и всё, на что ссылаются их манифесты. Код общий для репозиториев
// платформы и проверяется вместе с общим стендом: здесь его не правят.
//   DRY_RUN=1 node scripts/ghcr-cleanup.mjs  - только напечатать, что удалилось бы
import url from "node:url";

export const KEEP = Number(process.env.KEEP || 10);
export const PROD_DEPLOYS = Number(process.env.PROD_DEPLOYS || 3);
export const MAX_DELETE = Number(process.env.MAX_DELETE || 400);
export const MARGIN_MIN = 10;

const list = (s) => (s || "").split(",").map((x) => x.trim()).filter(Boolean);
const tags = (v) => v.metadata?.container?.tags || [];
const at = (v) => Date.parse(v.created_at);

export const tagOf = (sha) => `sha-${sha.slice(0, 12)}`;

export function keptImages(versions, { keep = KEEP, protect = [] } = {}) {
  const tagged = [...versions].sort((a, b) => at(b) - at(a)).filter((v) => tags(v).length);
  const newest = tagged.slice(0, keep);
  if (newest.length < keep) return null;
  const protectSet = new Set(protect);
  const kept = new Set(newest);
  for (const v of tagged) if (tags(v).some((t) => protectSet.has(t))) kept.add(v);
  return { kept: [...kept], oldestNewest: newest[newest.length - 1] };
}

export function plan(versions, { keep = KEEP, protect = [], marginMin = MARGIN_MIN, refs = new Set() } = {}) {
  const margin = marginMin * 60e3;
  const byNew = [...versions].sort((a, b) => at(b) - at(a));
  const k = keptImages(versions, { keep, protect });
  if (!k) return { keep: versions.map((v) => v.id), remove: [] }; // мало образов - не трогаем
  const cutoff = at(k.oldestNewest) - margin;
  const near = (u) => k.kept.some((x) => at(u) >= at(x) - margin && at(u) <= at(x) + margin);
  const keepIds = new Set(k.kept.map((v) => v.id));
  const remove = [];
  for (const v of byNew) {
    if (keepIds.has(v.id)) continue;
    if (!tags(v).length && (refs.has(v.name) || at(v) >= cutoff || near(v))) keepIds.add(v.id);
    else remove.push(v.id);
  }
  return { keep: [...keepIds], remove };
}

const MANIFEST_ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

export async function manifestChildren(owner, pkg, digest, { fetchImpl = fetch, tries = 4, pause = 2000, tokens = new Map() } = {}) {
  const repo = `${owner.toLowerCase()}/${pkg}`;
  const req = async (u, headers) => {
    for (let i = 1; ; i++) {
      let res;
      try {
        res = await fetchImpl(u, { method: "GET", headers });
      } catch (e) {
        if (i >= tries) throw new Error(`GET ${u}: ${e.message}`);
        await sleep(pause * i);
        continue;
      }
      if ((res.status >= 500 || res.status === 429) && i < tries) { await sleep(pause * i); continue; }
      if (!res.ok) throw new Error(`GET ${u}: ${res.status} ${await res.text()}`);
      return res.json();
    }
  };
  if (!tokens.has(repo)) {
    const basic = Buffer.from(`${process.env.GITHUB_ACTOR || "token"}:${process.env.GITHUB_TOKEN}`).toString("base64");
    const t = await req(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repo}:pull`, { Authorization: `Basic ${basic}` });
    if (!t?.token) throw new Error(`ghcr.io/token для ${repo}: в ответе нет token`);
    tokens.set(repo, t.token);
  }
  const m = await req(`https://ghcr.io/v2/${repo}/manifests/${digest}`, { Authorization: `Bearer ${tokens.get(repo)}`, Accept: MANIFEST_ACCEPT });
  return (m.manifests || []).map((x) => x.digest).filter(Boolean);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function gh(method, path, { fetchImpl = fetch, tries = 4, pause = 2000 } = {}) {
  if (process.env.DRY_RUN && method !== "GET") return null;
  const headers = { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  for (let i = 1; ; i++) {
    let res;
    try {
      res = await fetchImpl(`https://api.github.com${path}`, { method, headers });
    } catch (e) {
      if (i >= tries) throw new Error(`${method} ${path}: ${e.message}`);
      await sleep(pause * i);
      continue;
    }
    if (method === "DELETE" && res.status === 404) {
      const still = await fetchImpl(`https://api.github.com${path}`, { method: "GET", headers });
      if (still.status === 404) return null;
      throw new Error(`DELETE ${path}: 404, а версия на месте (GET ${still.status}) - у репозитория нет роли Admin в пакете: Package settings, Manage Actions access`);
    }
    if ((res.status >= 500 || res.status === 429) && i < tries) {
      await sleep(pause * i);
      continue;
    }
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
    return res.status === 204 ? null : res.json();
  }
}

export async function run(env = process.env, call = gh, children = manifestChildren) {
  const owner = env.GITHUB_REPOSITORY_OWNER;
  const repo = env.GITHUB_REPOSITORY;
  const keepN = Number(env.KEEP || KEEP);
  const packages = list(env.PACKAGES);
  if (!packages.length) throw new Error("PACKAGES пуст - нечего чистить");
  const deploys = await call("GET", `/repos/${repo}/deployments?environment=production&per_page=${Number(env.PROD_DEPLOYS || PROD_DEPLOYS)}`);
  if (!Array.isArray(deploys)) throw new Error("выкатки не прочитаны - не удаляю ничего");
  const protect = [...new Set([...deploys.map((d) => tagOf(d.sha)), ...list(env.PROTECT_TAGS)])];
  console.log(`защищены: ${protect.join(" ") || "-"}`);
  let budget = Number(env.MAX_DELETE || MAX_DELETE);
  let total = 0;
  for (const pkg of packages) {
    const base = `/users/${owner}/packages/container/${pkg}/versions`;
    const versions = [];
    for (let page = 1; page <= 50; page++) {
      const batch = await call("GET", `${base}?per_page=100&page=${page}`);
      versions.push(...batch);
      if (batch.length < 100) break;
    }
    const refs = new Set();
    for (const v of keptImages(versions, { keep: keepN, protect })?.kept || []) {
      if (!v.name) continue;
      for (const d of await children(owner, pkg, v.name)) refs.add(d);
    }
    const { keep, remove } = plan(versions, { keep: keepN, protect, refs });
    const now = remove.slice(0, budget);
    console.log(`${pkg}: версий ${versions.length}, оставить ${keep.length}, детей в манифестах оставленных ${refs.size}, удалить ${remove.length}, в этом прогоне ${now.length}${env.DRY_RUN ? " (DRY_RUN)" : ""}`);
    let done = 0;
    for (const id of now) {
      await call("DELETE", `${base}/${id}`);
      done++;
      if (done % 100 === 0 && !env.DRY_RUN) console.log(`${pkg}: удалено ${done}`);
    }
    budget -= now.length;
    total += now.length;
    const left = remove.length - now.length;
    console.log(`${pkg}: удалено ${env.DRY_RUN ? 0 : done}${left ? `, осталось на следующие прогоны ${left}` : ""}`);
  }
  return total;
}

if (import.meta.url === url.pathToFileURL(process.argv[1] || "").href) {
  run().catch((e) => { console.error(e.message); process.exit(1); });
}
