#!/usr/bin/env python3
"""hexsum: file_safely module to read files in chunks."""


from collections.abc import Generator
from pathlib import Path
from typing import Any

from rich import print
from rich.panel import Panel
from typer import Exit


# ~~~ #
def read_file_in_chunks(
        file_path: Path,
        read_size: int,
) -> Generator[bytes, Any, None]:
    try:
        with Path.open(self=file_path, mode='rb') as f:
            while read_data := f.read(read_size):
                yield read_data
    except OSError as e:
        print(Panel(
            f'cannot read file: {file_path}\n{e}.',
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
        raise Exit from OSError
