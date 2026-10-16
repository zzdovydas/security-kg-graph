"""
Read-only perturbation test on the CVE/CWE/CAPEC graph.
Edges are "removed" only by excluding them from the shortestPath search;
nothing is changed in the database. Results are drawn as bubble graphs.

At each step the current shortest path is taken and the hop just before
the target is excluded (3rd-to-last <-> 2nd-to-last node). Incoming
edges to CWE-14 are left alone — except CWE-733 <-> CWE-14, which is
cut when it is the last hop — until no path remains.

pip install neo4j networkx matplotlib
"""
import math
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4jpassword"))

SRC, TARGET = "CWE-284", "CWE-279"
RELS = "CHILD_OF|PARENT_OF|RELATED_WEAKNESS|RELATED_ATTACK_PATTERN"
LABELS = ["CWE", "CAPEC", "CVE"]     # node types a path may pass through
MAX_HOPS = 8                        # keep modest: CVE nodes make the graph very wide
MAX_STEPS = 10
MAX_DISPLAY = 4                     # never draw more than this many panels

COLORS = {"CWE": "#4C78A8", "CAPEC": "#F58518", "CVE": "#54A24B"}


# ---------------------------------------------------------------- queries
def run(query, **params):
    return driver.execute_query(query, params, database_="neo4j", routing_="r").records


def edges_between(a, b):
    """ALL relationships (any type, both directions) between two nodes."""
    return [dict(r) for r in run("""
        MATCH (x {id:$a})-[r]-(y {id:$b})
        RETURN DISTINCT elementId(r) AS rid,
               head(labels(startNode(r))) + ':' + startNode(r).id AS src,
               head(labels(endNode(r)))   + ':' + endNode(r).id   AS dst,
               type(r) AS rel
    """, a=a, b=b)]


def shortest(removed_ids):
    rec = run(f"""
        MATCH (a:CWE {{id:$src}}), (b:CWE {{id:$dst}})
        MATCH p = shortestPath((a)-[:{RELS}*..{MAX_HOPS}]-(b))
        WHERE all(n IN nodes(p) WHERE any(l IN labels(n) WHERE l IN $labels))
          AND none(r IN relationships(p) WHERE elementId(r) IN $removed)
        RETURN [n IN nodes(p) | head(labels(n)) + ':' + n.id] AS nodes,
               [r IN relationships(p) | type(r)] AS rels
    """, src=SRC, dst=TARGET, labels=LABELS, removed=list(removed_ids))
    if not rec:
        return None
    return rec[0]["nodes"], rec[0]["rels"]


def test(title, removed_edges):
    path = shortest({e["rid"] for e in removed_edges})
    return {"title": title, "removed": removed_edges, "path": path}


def node_id(key):
    """'CWE:CWE-435' -> 'CWE-435'."""
    return key.split(":", 1)[1]


def hop_ids(a, b):
    return {node_id(a), node_id(b)}


def pair_to_cut(nodes):
    """Hop to exclude on this shortest path, working from the target end.

    The last hop into CWE-14 is never cut, except CWE-733 <-> CWE-14.
    Otherwise cut the hop before that: 3rd-to-last <-> 2nd-to-last
    (e.g. CWE-226 <-> CVE-2026-48984).
    """
    if len(nodes) < 3:
        return None
    last_a, last_b = nodes[-2], nodes[-1]
    if hop_ids(last_a, last_b) == {"CWE-733", TARGET}:
        return last_a, last_b
    if TARGET in hop_ids(last_a, last_b):
        return nodes[-3], nodes[-2]
    return None


def short_label(key):
    """'CVE:CVE-2026-40165' -> 'CVE\\n2026-40165' (fits inside a bubble)."""
    return key.split(":", 1)[1].replace("-", "\n", 1)


def removed_pairs(step):
    """{(src, dst): 'PARENT_OF/CHILD_OF'}: parallel edges merged into one dashed line."""
    pairs = {}
    for e in step["removed"]:
        key = tuple(sorted((e["src"], e["dst"])))
        pairs.setdefault(key, set()).add(e["rel"])
    return {k: "/".join(sorted(v)) for k, v in pairs.items()}


def collect_steps():
    removed = []
    steps = [test("Baseline (nothing removed)", [])]
    print("Baseline:", end=" ")
    if steps[0]["path"]:
        print(f"{len(steps[0]['path'][1])} hops  {' -> '.join(steps[0]['path'][0])}")
    else:
        print("NO PATH")

    while len(steps) < MAX_STEPS:
        path = steps[-1]["path"]
        if not path:
            break
        nodes, _rels = path
        pair = pair_to_cut(nodes)
        if not pair:
            print("Stopped: next cut would remove a last-hop into CWE-14")
            break
        a, b = node_id(pair[0]), node_id(pair[1])
        already = {e["rid"] for e in removed}
        new_edges = [e for e in edges_between(a, b) if e["rid"] not in already]
        if not new_edges:
            print(f"Stopped: no unused relationships between {a} and {b}")
            break
        removed = removed + new_edges
        step = test(f"Step {len(steps)}: remove {a} <-> {b}", list(removed))
        steps.append(step)
        if step["path"]:
            hops = len(step["path"][1])
            print(f"Step {len(steps) - 1}: removed {len(new_edges)} rels "
                  f"({len(removed)} total) {a} <-> {b} -> {hops} hops  "
                  f"{' -> '.join(step['path'][0])}")
        else:
            print(f"Step {len(steps) - 1}: removed {len(new_edges)} rels "
                  f"({len(removed)} total) {a} <-> {b} -> NO PATH")
    return steps


def spread_positions(pos, min_dist=0.55, rounds=120):
    """Push overlapping nodes apart so bubbles do not sit on top of each other."""
    nodes = list(pos)
    coords = {n: np.array(pos[n], dtype=float) for n in nodes}
    for _ in range(rounds):
        moved = False
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                delta = coords[b] - coords[a]
                dist = float(np.linalg.norm(delta))
                if dist < 1e-9:
                    delta = np.array([0.15, 0.08])
                    dist = float(np.linalg.norm(delta))
                if dist < min_dist:
                    push = ((min_dist - dist) / 2.0) * delta / dist
                    coords[a] -= push
                    coords[b] += push
                    moved = True
        if not moved:
            break
    return {n: (float(c[0]), float(c[1])) for n, c in coords.items()}


def pick_display_steps(steps, k=MAX_DISPLAY):
    """Evenly sample at most k steps, always keeping the first and last."""
    if len(steps) <= k:
        return steps
    idxs = [round(i * (len(steps) - 1) / (k - 1)) for i in range(k)]
    chosen = []
    for i in idxs:
        if i not in chosen:
            chosen.append(i)
    return [steps[i] for i in chosen]


def plot_steps(steps):
    shown = pick_display_steps(steps)
    print(f"Displaying {len(shown)} of {len(steps)} steps")

    # Shared layout from the displayed paths only (not every accumulated cut)
    U = nx.Graph()
    for s in shown:
        if s["path"]:
            nx.add_path(U, s["path"][0])
        for (a, b) in removed_pairs(s):
            if a in U and b in U:
                U.add_edge(a, b)
    n_nodes = max(len(U), 1)
    pos = nx.spring_layout(U, seed=7, k=6.0 / math.sqrt(n_nodes), iterations=500, scale=5.0)
    pos = spread_positions(pos, min_dist=1.45)
    ys = [p[1] for p in pos.values()] or [0.0]
    label_dy = 0.07 * max((max(ys) - min(ys)), 1.0)

    n = len(shown)
    ncols = 5 if n > 5 else 2
    nrows = math.ceil(n / ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(6.8 * ncols, 7.4 * nrows))
    axes = [axes] if nrows * ncols == 1 else list(axes.flat)
    src_key = next(key for key in U if key.endswith(":" + SRC))
    dst_key = next(key for key in U if key.endswith(":" + TARGET))

    for ax, step in zip(axes, shown):
        ax.set_axis_off()

        # faint context: every node/edge seen in a shown step
        nx.draw_networkx_edges(U, pos, ax=ax, edge_color="#d0d0d0", width=1)
        nx.draw_networkx_nodes(U, pos, ax=ax, node_color="#e6e6e6", node_size=1400, alpha=0.55)
        nx.draw_networkx_labels(U, pos, ax=ax, labels={n: short_label(n) for n in U},
                                font_size=7, font_color="#aaaaaa")

        # removed relationships: red dashed
        rp = {k: v for k, v in removed_pairs(step).items() if k[0] in U and k[1] in U}
        if rp:
            nx.draw_networkx_edges(U, pos, ax=ax, edgelist=list(rp), edge_color="#d62728",
                                   style="dashed", width=2.5)
            nx.draw_networkx_edge_labels(U, pos, ax=ax, font_size=7, font_color="#d62728",
                                         edge_labels={k: "removed\n" + v for k, v in rp.items()})

        # the shortest path: coloured bubbles + solid edges
        if step["path"]:
            nodes, rels = step["path"]
            edgelist = list(zip(nodes, nodes[1:]))
            nx.draw_networkx_edges(U, pos, ax=ax, edgelist=edgelist, edge_color="#222222", width=3.5)
            nx.draw_networkx_edge_labels(U, pos, ax=ax, font_size=7, rotate=False,
                                         edge_labels=dict(zip(edgelist, rels)))
            nx.draw_networkx_nodes(
                U, pos, ax=ax, nodelist=nodes, node_size=2000,
                node_color=[COLORS[n.split(":")[0]] for n in nodes],
                edgecolors=["black" if n in (src_key, dst_key) else "white" for n in nodes],
                linewidths=[3.5 if n in (src_key, dst_key) else 1.5 for n in nodes],
            )
            nx.draw_networkx_labels(U, pos, ax=ax, labels={n: short_label(n) for n in nodes},
                                    font_size=8, font_color="white", font_weight="bold")
            for key, text in ((src_key, "START"), (dst_key, "TARGET")):
                x, y = pos[key]
                ax.text(x, y + label_dy, text, ha="center", fontsize=9, fontweight="bold")
            ax.set_title(f"{step['title']}\nshortest path: {len(rels)} hops", fontsize=11)
        else:
            ax.set_title(f"{step['title']}\nNO PATH", fontsize=11, color="#d62728")

        ax.margins(0.28)

    for ax in axes[len(shown):]:
        ax.set_axis_off()
        ax.set_visible(False)

    fig.legend(
        handles=[
            Patch(color=COLORS["CWE"], label="CWE"),
            Patch(color=COLORS["CAPEC"], label="CAPEC"),
            Patch(color=COLORS["CVE"], label="CVE"),
            Line2D([0], [0], color="#222222", lw=3, label="shortest path"),
            Line2D([0], [0], color="#d62728", lw=2.5, ls="--", label="removed relationship"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="#e6e6e6",
                   markeredgecolor="black", markeredgewidth=3, markersize=12, label="start / target"),
        ],
        loc="lower center", ncol=6, frameon=False, fontsize=10,
    )
    fig.suptitle(f"Perturbation test: {SRC}  \u2192  {TARGET}", fontsize=15, fontweight="bold")
    fig.tight_layout(rect=[0, 0.05, 1, 0.96])
    fig.savefig("perturbation_paths.png", dpi=120)
    plt.show()


if __name__ == "__main__":
    plot_steps(collect_steps())
