"""Minimal hierarchy drawer used as ``from tree_pdf import from_dict, draw_tree``."""
from dataclasses import dataclass, field

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import FancyBboxPatch


CWE_COLORS = {
    "Pillar": "#DAA520",
    "Class": "#FFFFAA",
    "Base": "#CCFFFF",
    "Variant": "#CCAAFF",
    "Compound": "#FFFFFF",
    "Category": "#FFAAAA",
}


@dataclass
class TreeNode:
    id: str
    name: str
    kind: str | None = None
    edge: list | str | None = None
    color: str | None = None
    children: list = field(default_factory=list)
    x: float = 0.0
    y: float = 0.0


def _normalize_edge(edge):
    if not edge:
        return None
    if isinstance(edge, list):
        return edge
    return [{"text": str(edge), "value": None}]


def _score_style(value):
    if value is None:
        return "#FFFFFF", "#000000"
    if value < 0.2:
        return "#D32F2F", "#FFFFFF"
    if value < 0.6:
        return "#F4D03F", "#000000"
    return "#2E7D32", "#FFFFFF"


def from_dict(data):
    kind = data.get("kind")
    return TreeNode(
        id=str(data["id"]),
        name=str(data.get("name", "")),
        kind=kind,
        edge=_normalize_edge(data.get("edge")),
        color=data.get("color") or CWE_COLORS.get(kind, "#eef3f8"),
        children=[from_dict(c) for c in data.get("children", [])],
    )


def _leaf_count(node):
    if not node.children:
        return 1
    return sum(_leaf_count(c) for c in node.children)


def _layout(node, x, y, x_gap, y_gap):
    """Left-to-right: depth along x, siblings along y. Returns next y."""
    if not node.children:
        node.x, node.y = x, y
        return y + y_gap
    start = y
    for child in node.children:
        y = _layout(child, x + x_gap, y, x_gap, y_gap)
    node.x = x
    node.y = (start + y - y_gap) / 2.0
    return y


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _label(node, max_len=42):
    text = f"{node.id} {node.name}".strip()
    if node.kind:
        text = f"{text} [{node.kind}]"
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def _draw_node(ax, node, box_w, box_h):
    x, y = node.x, node.y
    box = FancyBboxPatch(
        (x - box_w / 2, y - box_h / 2), box_w, box_h,
        boxstyle="round,pad=0.03,rounding_size=0.08",
        facecolor=node.color or "#eef3f8", edgecolor="#2c3e50", linewidth=1.1,
    )
    ax.add_patch(box)
    ax.text(x, y, _label(node), ha="center", va="center", fontsize=6.5)
    if node.edge:
        _draw_score_boxes(ax, x, y - box_h / 2 - 0.10, node.edge)


def _draw_score_boxes(ax, cx, cy, scores):
    w, h, gap = 0.50, 0.155, 0.035
    total = len(scores) * w + max(len(scores) - 1, 0) * gap
    x0 = cx - total / 2
    for i, item in enumerate(scores):
        text, value = item["text"], item.get("value")
        bg, fg = _score_style(value)
        x = x0 + i * (w + gap)
        ax.add_patch(FancyBboxPatch(
            (x, cy - h / 2), w, h,
            boxstyle="square,pad=0",
            facecolor=bg, edgecolor="black", linewidth=0.8,
        ))
        ax.text(x + w / 2, cy, text, ha="center", va="center",
                fontsize=5, color=fg, fontweight="bold")


def _draw_edges_from(ax, parent, box_w):
    """Orthogonal parent→children connectors; labels sit on each child's stub."""
    kids = parent.children
    if not kids:
        return
    color = "#4a5568"
    x_out = parent.x + box_w / 2
    x_bus = x_out + 0.22
    ys = [parent.y] + [c.y for c in kids]
    ax.plot([x_out, x_bus], [parent.y, parent.y], color=color, lw=1)
    ax.plot([x_bus, x_bus], [min(ys), max(ys)], color=color, lw=1)
    for child in kids:
        x_in = child.x - box_w / 2
        ax.plot([x_bus, x_in], [child.y, child.y], color=color, lw=1)


def draw_tree(roots, path, title=""):
    if not roots:
        raise ValueError("draw_tree needs at least one root")

    x_gap, y_gap = 3.65, 0.78
    box_w, box_h = 2.85, 0.28
    cursor = 0.0
    max_depth = 1
    for root in roots:
        cursor = _layout(root, 0.0, cursor, x_gap, y_gap) + 0.4
        max_depth = max(max_depth, max(int(round(n.x / x_gap)) + 1 for n in _walk(root)))

    height = max(cursor, 4)
    width = max(max_depth * x_gap + 1.4, 8)
    fig_w = min(max(width * 0.95, 12), 32)
    fig_h = min(max(height * 1.15, 8), 22)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_axis_off()
    if title:
        ax.set_title(title, fontsize=13, fontweight="bold", pad=12)

    for root in roots:
        nodes = list(_walk(root))
        for node in nodes:
            _draw_edges_from(ax, node, box_w)
        for node in nodes:
            _draw_node(ax, node, box_w, box_h)

    ax.set_xlim(-1.4, width)
    ax.set_ylim(-0.5, height + 0.7)
    ax.invert_yaxis()

    legend_y = height + 0.35
    legend_x = -1.1
    for label, color in (("Pillar", "#DAA520"), ("Class", "#FFFFAA"),
                         ("Base", "#CCFFFF"), ("Variant", "#CCAAFF")):
        ax.add_patch(FancyBboxPatch(
            (legend_x, legend_y - 0.08), 0.28, 0.16,
            boxstyle="round,pad=0.01,rounding_size=0.04",
            facecolor=color, edgecolor="#2c3e50", linewidth=0.8,
        ))
        ax.text(legend_x + 0.34, legend_y, label, ha="left", va="center", fontsize=6.5)
        legend_x += 1.7

    fig.tight_layout()
    with PdfPages(path) as pdf:
        pdf.savefig(fig)
    plt.close(fig)
