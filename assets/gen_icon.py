"""生成 Clash Generator 多分辨率 ICO 图标。

使用 Pillow 直接绘制图标，无需外部依赖。
图标风格：蓝色渐变圆形 + 白色波形/代理符号。
"""
from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image, ImageDraw


def create_icon(size: int) -> Image.Image:
    """创建指定尺寸的图标。

    设计：蓝色渐变圆形背景 + 白色波形代理图标。

    Args:
        size: 图标尺寸

    Returns:
        PIL Image（RGBA 模式）
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx, cy = size / 2, size / 2
    radius = int(size * 0.42)

    # 1. 绘制蓝色渐变圆形背景
    for r in range(radius, 0, -1):
        # 从中心的深蓝到边缘的浅蓝渐变
        t = 1.0 - r / radius  # 0 边缘 -> 1 中心
        red = int(25 + (41 - 25) * t)
        green = int(118 + (182 - 118) * t)
        blue = int(210 + (246 - 210) * t)
        draw.ellipse(
            [cx - r, cy - r, cx + r, cy + r],
            fill=(red, green, blue, 255),
        )

    # 2. 绘制波形/代理符号（三条弧形信号波）
    stroke_width = max(2, size // 16)
    wave_color = (255, 255, 255, 230)

    # 波形参数（基于图标中心）
    wave_center_y = int(cy + size * 0.05)
    wave_spacing = max(3, size // 8)

    # 绘制三条信号波弧线（类似 WiFi 信号）
    for i in range(3):
        arc_radius = int(radius * 0.35 + i * wave_spacing)
        # 从左下到右下的弧形（底部开口的半圆）
        bbox = [
            int(cx - arc_radius),
            int(wave_center_y - arc_radius),
            int(cx + arc_radius),
            int(wave_center_y + arc_radius),
        ]
        # 起始角度 200 度，终止角度 340 度（底部弧形）
        draw.arc(bbox, start=200, end=340, fill=wave_color, width=stroke_width)

    # 3. 绘制底部小圆点（信号源）
    dot_radius = max(2, size // 12)
    dot_y = int(wave_center_y + radius * 0.38)
    draw.ellipse(
        [cx - dot_radius, dot_y - dot_radius, cx + dot_radius, dot_y + dot_radius],
        fill=(255, 255, 255, 255),
    )

    return img


def save_ico(images: list[tuple[Image.Image, int]], output_path: Path) -> None:
    """将多个尺寸的图像保存为 ICO 文件。

    Args:
        images: [(PIL Image, size), ...]
        output_path: 输出路径
    """
    png_datas = []
    for img, size in images:
        import io
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_datas.append((buf.getvalue(), size, size))

    # 构建 ICO 文件
    entries = []
    for png_data, w, h in png_datas:
        entries.append({
            "w": w if w < 256 else 0,
            "h": h if h < 256 else 0,
            "data_size": len(png_data),
            "png": png_data,
        })

    header_size = 6
    entry_size = 16
    dir_size = header_size + entry_size * len(entries)

    result = bytearray()
    result.extend(struct.pack("<HHH", 0, 1, len(entries)))

    offset = dir_size
    for e in entries:
        result.extend(struct.pack(
            "<BBBBHHII",
            e["w"], e["h"], 0, 0, 1, 32, e["data_size"], offset,
        ))
        offset += e["data_size"]

    for e in entries:
        result.extend(e["png"])

    output_path.write_bytes(bytes(result))


def main() -> None:
    """生成多分辨率 ICO 图标。"""
    sizes = [16, 24, 32, 48, 64, 128, 256]

    images = []
    for size in sizes:
        print(f"  创建 {size}x{size} 图标...")
        img = create_icon(size)
        images.append((img, size))

    output_dir = Path(__file__).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    ico_path = output_dir / "app.ico"

    save_ico(images, ico_path)

    # 同时保存 256x256 的 PNG 作为备用
    png_path = output_dir / "app.png"
    images[-1][0].save(png_path, format="PNG")

    print(f"\n✅ 图标已生成:")
    print(f"   ICO: {ico_path}")
    print(f"   PNG: {png_path}")
    print(f"   包含 {len(sizes)} 种尺寸: {sizes}")


if __name__ == "__main__":
    main()