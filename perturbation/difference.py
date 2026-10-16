"""
Compare parent/child CWE nodes around SRC and TARGET.

Walks downward from SRC (CWE-285) along PARENT_OF only — never up to a
more abstract parent. Scores each parent→child pair with TF-IDF and
sentence-transformer embeddings. Draws the hierarchy with tree_pdf.

pip install neo4j scikit-learn sentence-transformers matplotlib
"""
import matplotlib.pyplot as plt
import numpy as np
from neo4j import GraphDatabase
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from tree_pdf import from_dict, draw_tree

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4jpassword"))

SEEDS = ["CWE-285", "CWE-732", "CWE-279"]
SRC, TARGET = SEEDS[0], SEEDS[-1]
EMBED_MODEL = "all-MiniLM-L6-v2"
TOP_TERMS = 6


def run(query, **params):
    return driver.execute_query(query, params, database_="neo4j", routing_="r").records


def suffix_key(name):
    tail = name.rsplit("_", 1)[-1]
    return (0, int(tail)) if tail.isdigit() else (1, name)


def values_with_prefix(props, prefix):
    keys = [k for k in props if k == prefix or k.startswith(prefix + "_")]
    keys.sort(key=suffix_key)
    out, seen = [], set()
    for k in keys:
        val = props[k]
        if val is None:
            continue
        text = str(val).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def first_with_prefix(props, prefix, default=""):
    vals = values_with_prefix(props, prefix)
    return vals[0] if vals else default


def node_from_props(cid, props):
    description = " ".join(values_with_prefix(props, "description"))
    scopes = values_with_prefix(props, "consequence_scope")
    return {
        "id": cid,
        "name": first_with_prefix(props, "name", cid),
        "abstraction": first_with_prefix(props, "abstraction", "?"),
        "description": description,
        "scope_text": "; ".join(scopes),
        "combined": (description + " " + "; ".join(scopes)).strip(),
    }


def fetch_descendants(src, seeds=None):
    """SRC and every descendant via PARENT_OF. Never walk to a parent of SRC."""
    recs = run("""
        MATCH (src:CWE {id:$src})-[:PARENT_OF*0..8]->(n:CWE)
        RETURN DISTINCT n.id AS id, properties(n) AS props
    """, src=src)
    nodes = {r["id"]: node_from_props(r["id"], dict(r["props"])) for r in recs}

    edge_recs = run("""
        MATCH (src:CWE {id:$src})-[:PARENT_OF*0..7]->(a:CWE)-[:PARENT_OF]->(b:CWE)
        RETURN DISTINCT a.id AS parent, b.id AS child
    """, src=src)
    edges = [(r["parent"], r["child"]) for r in edge_recs]
    return nodes, edges


def tfidf_matrices(texts):
    vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1)
    matrix = vec.fit_transform(texts)
    return vec, matrix, cosine_similarity(matrix)


def embed_matrix(texts, model):
    vectors = model.encode(texts, normalize_embeddings=True)
    return cosine_similarity(vectors)


def distinctive_terms(vec, matrix, i, j, k=TOP_TERMS):
    names = np.array(vec.get_feature_names_out())
    delta = np.asarray(matrix[i].todense()).ravel() - np.asarray(matrix[j].todense()).ravel()

    def top(want_positive):
        scores = delta if want_positive else -delta
        picked = []
        for idx in np.argsort(scores)[::-1]:
            if scores[idx] <= 0:
                break
            picked.append(names[idx])
            if len(picked) >= k:
                break
        return picked

    return top(True), top(False)


def print_nodes(nodes):
    print(f"\nDescendants of {SRC}  ({len(nodes)} CWE nodes, downward only)")
    print("-" * 88)
    for nid in sorted(nodes, key=lambda x: int(x.split("-")[1])):
        n = nodes[nid]
        mark = " *" if nid in SEEDS else ""
        print(f"{n['id']:10}  {n['abstraction']:8}  {n['name']}{mark}")
        print(f"            {n['description'][:140]}")
        print(f"            scope: {n['scope_text'] or '(none)'}")
        print()


def print_parent_child(nodes, edges, index, field_scores, desc_vec, desc_mat):
    print("Parent → child similarity / difference  (difference = 1 - cosine)")
    print("-" * 88)
    print(f"{'edge':<22} {'field':<12} {'tfidf_sim':>9} {'tfidf_diff':>10} {'emb_sim':>8} {'emb_diff':>8}")
    for parent, child in edges:
        i, j = index[parent], index[child]
        pair = f"{parent} → {child}"
        for field, tfidf, emb in field_scores:
            ts, es = tfidf[i, j], emb[i, j]
            print(f"{pair:<22} {field:<12} {ts:9.3f} {1 - ts:10.3f} {es:8.3f} {1 - es:8.3f}")
        hi_terms, lo_terms = distinctive_terms(desc_vec, desc_mat, i, j)
        print(f"{'':22} parent terms: {', '.join(hi_terms) or '(none)'}")
        print(f"{'':22} child terms:  {', '.join(lo_terms) or '(none)'}")
        print()


def build_forest(nodes, edges, scores):
    """Single tree rooted at SRC; only downward PARENT_OF children."""
    children = {}
    for parent, child in edges:
        children.setdefault(parent, []).append(child)
    for kids in children.values():
        kids.sort(key=lambda x: int(x.split("-")[1]))

    roots = [SRC] if SRC in nodes else []

    expanded = set()

    def to_dict(nid, incoming=None):
        n = nodes[nid]
        first_visit = nid not in expanded
        expanded.add(nid)
        item = {
            "id": nid.replace("CWE-", ""),
            "name": n["name"],
            "kind": n["abstraction"],
            "color": {
                "Pillar": "#DAA520", "Class": "#FFFFAA",
                "Base": "#CCFFFF", "Variant": "#CCAAFF",
            }.get(n["abstraction"], "#eef3f8"),
        }
        if incoming:
            item["edge"] = incoming
        kids = children.get(nid, []) if first_visit else []
        item["children"] = [to_dict(cid, scores.get((nid, cid))) for cid in kids]
        return item

    return [to_dict(rid) for rid in roots]


def plot_heatmaps(ids, tfidf_sim, emb_sim, path="cwe_diff_heatmap.png"):
    fig, axes = plt.subplots(1, 2, figsize=(max(8, 0.45 * len(ids) + 4),) * 2)
    labels = [i.replace("CWE-", "") for i in ids]
    for ax, data, title in (
        (axes[0], tfidf_sim, "TF-IDF cosine"),
        (axes[1], emb_sim, "MiniLM cosine"),
    ):
        im = ax.imshow(data, vmin=0, vmax=1, cmap="YlGn")
        ax.set_title(title)
        ax.set_xticks(range(len(labels)), labels, rotation=90, fontsize=7)
        ax.set_yticks(range(len(labels)), labels, fontsize=7)
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.suptitle("CWE neighborhood similarity (combined description + scope)",
                 fontsize=12, fontweight="bold")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    print(f"Saved {path}")


def main():
    nodes, edges = fetch_descendants(SRC, SEEDS)
    edges = sorted(set(edges), key=lambda e: (int(e[0].split("-")[1]), int(e[1].split("-")[1])))
    ids = sorted(nodes, key=lambda x: int(x.split("-")[1]))
    index = {nid: i for i, nid in enumerate(ids)}
    print_nodes(nodes)

    fields = {
        "description": [nodes[i]["description"] or " " for i in ids],
        "scope": [nodes[i]["scope_text"] or " " for i in ids],
        "combined": [nodes[i]["combined"] or " " for i in ids],
    }

    print("Loading embedding model", EMBED_MODEL, "...")
    model = SentenceTransformer(EMBED_MODEL)

    field_scores = []
    desc_vec = desc_mat = None
    combined_tfidf = combined_emb = None
    for name, texts in fields.items():
        vec, mat, tfidf_sim = tfidf_matrices(texts)
        emb_sim = embed_matrix(texts, model)
        field_scores.append((name, tfidf_sim, emb_sim))
        if name == "description":
            desc_vec, desc_mat = vec, mat
        if name == "combined":
            combined_tfidf, combined_emb = tfidf_sim, emb_sim

    print_parent_child(nodes, edges, index, field_scores, desc_vec, desc_mat)

    edge_labels = {}
    for parent, child in edges:
        i, j = index[parent], index[child]
        ts, es = float(combined_tfidf[i, j]), float(combined_emb[i, j])
        edge_labels[(parent, child)] = [
            {"text": f"tfidf {ts:.2f}", "value": ts},
            {"text": f"emb {es:.2f}", "value": es},
        ]
    forest = build_forest(nodes, edges, edge_labels)
    draw_tree([from_dict(d) for d in forest], "cwe_diff_tree.pdf",
              title=f"CWE descendants of {SRC}  (parent → child similarity)")
    print("Saved cwe_diff_tree.pdf")
    plot_heatmaps(ids, combined_tfidf, combined_emb)


if __name__ == "__main__":
    main()
