"""将 SVG 图标转换为多分辨率 ICO 文件（纯 Python 实现，无需 Cairo）。

使用 svglib + reportlab 渲染 SVG，Pillow 转换为 ICO。
"""
from __future__ import annotations

import struct
from pathlib import Path


def svg_to_png(svg_path: Path, size: int) -> bytes:
    """使用 svglib + reportlab 将 SVG 渲染为 PNG。"""
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPM

    drawing = svg2rlg(str(svg_path))
    if drawing is None:
        raise RuntimeError(f"无法加载 SVG: {svg_path}")

    # 缩放至目标尺寸（SVG 原始尺寸为 24x24）
    scale = size / 24.0
    drawing.scale(scale, scale)

    import io
    buf = io.BytesIO()
    renderPM.drawToFile(drawing, buf, fmt="PNG", dpi=72)
    return buf.getvalue()


def png_to_ico_pngdata(png_data_list: list[tuple[bytes, int, int]]) -> bytes:
    """创建 ICO 文件（每个图标使用 PNG 压缩格式，Windows Vista+ 支持）。

    Args:
        png_data_list: [(png_bytes, width, height), ...]

    Returns:
        ICO 文件字节
    """
    # 收集图标条目
    entries = []
    for png_data, w, h in png_data_list:
        entries.append({
            "width": w if w < 256 else 0,
            "height": h if h < 256 else 0,
            "color_count": 0,
            "reserved": 0,
            "planes": 1,
            "bit_count": 32,
            "data_size": len(png_data),
            "image_data": png_data,
        })

    # 计算偏移
    header_size = 6  # ICONDIR
    entry_size = 16  # ICONDIRENTRY
    dir_size = header_size + entry_size * len(entries)

    # 构建 ICO
    result = bytearray()

    # ICONDIR
    result.extend(struct.pack("<HHH", 0, 1, len(entries)))

    # 计算每个图标的数据偏移
    offset = dir_size
    for e in entries:
        result.extend(struct.pack(
            "<BBBBHHII",
            e["width"],
            e["height"],
            e["color_count"],
            e["reserved"],
            e["planes"],
            e["bit_count"],
            e["data_size"],
            offset,
        ))
        offset += e["data_size"]

    # 写入图标数据
    for e in entries:
        result.extend(e["image_data"])

    return bytes(result)


def main() -> None:
    """主函数。"""
    svg_path = Path(__file__).parent / "app.svg"
    ico_path = Path(__file__).parent / "app.ico"

    if not svg_path.exists():
        print(f"❌ SVG 文件不存在: {svg_path}")
        return

    # Windows ICO 常用尺寸
    sizes = [16, 24, 32, 48, 64, 128, 256]
    png_list = []

    for size in sizes:
        print(f"  渲染 {size}x{size}...")
        try:
            png_data = svg_to_png(svg_path, size)
            png_list.append((png_data, size, size))
            print(f"    ✅ {len(png_data)} bytes")
        except Exception as e:
            print(f"    ⚠️  失败: {e}")

    if png_list:
        ico_data = png_to_ico_pngdata(png_list)
        ico_path.write_bytes(ico_data)
        print(f"\n✅ ICO 已生成: {ico_path}")
        print(f"   包含 {len(png_list)} 种尺寸: {[s for _, s, _ in png_list]}")
        print(f"   总大小: {len(ico_data)} bytes")
    else:
        print("❌ 所有尺寸转换均失败")


if __name__ == "__main__":
    main()