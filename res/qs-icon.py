import os
import sys
from typing import NamedTuple

class Icon(NamedTuple):
    filename: str
    size: int

def system2(cmd):
    exit_code = os.system(cmd)
    if exit_code != 0:
        sys.stderr.write(f"Error occurred when executing: `{cmd}`. Exiting.\n")
        sys.exit(-1)

def main():
    print("Setup the aplication icons")
    icon_path =  "res/logo-qs.png"

    icons: list[Icon] = [
        Icon(filename="icon.png", size=1024),
        Icon(filename="32x32.png", size=32),
        Icon(filename="64x64.png", size=64),
        Icon(filename="128x128.png", size=128),
        Icon(filename="128x128@2x.png", size=256),
        Icon(filename="mac-icon.png", size=1024),
    ]

    for icon in icons:
        print(f"creating the icon {icon}")
        path = os.path.join("res", icon.filename)
        system2(f"magick {icon_path} -colors 256 -resize {icon.size}x{icon.size} {path}")

    print("creating the .ico files")
    system2(f"magick convert {icon_path} -define icon:auto-resize=16,32,48,64,128,256 -compress zip res/icon.ico")
    system2(f"magick convert {icon_path} -define icon:auto-resize=32 -compress zip res/tray-icon.ico")

if __name__ == "__main__":
    main()

