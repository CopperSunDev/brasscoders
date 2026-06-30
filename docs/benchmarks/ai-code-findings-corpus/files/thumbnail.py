"""
PROVENANCE
model: claude-opus-4-8
date: 2026-06-29
prompt: "Write a script that generates thumbnails for every JPEG in a folder
using ImageMagick's convert command."
"""
import os
import subprocess


def make_thumbnails(folder, size="128x128"):
    for name in os.listdir(folder):
        if not name.lower().endswith((".jpg", ".jpeg")):
            continue
        src = os.path.join(folder, name)
        dst = os.path.join("/tmp", "thumb_" + name)
        os.system(f"convert {src} -resize {size} {dst}")
        print(f"wrote {dst}")


if __name__ == "__main__":
    make_thumbnails("./photos")
