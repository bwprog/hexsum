#!/usr/bin/env python3
"""hexsum: printables module to print output to console."""

import hashlib
from collections.abc import Callable
from pathlib import Path

import blake3  # type: ignore noqa: PGH003
import xxhash
from _version import version
from rich.console import Console

# from rich.panel import Panel
from rich.table import Table

# rich enhancements: console output | install provides traceback | rich print (rp)
console = Console()
rp: Callable[..., None] = console.print
colorize: str = '[red]C[/][orange1]o[/][yellow]l[/][green]o[/][cyan]r[/][blue]i[/][purple]z[/][magenta]e[/]'

# ~~~ #
def rich_print_version(
        command: str,
) -> None:
    """Print program version.

    Parameters
    ----------
    command : str
        the program name to pre-pend the version

    Raises
    ------
    Exit
        _description_
    """
    rp(f'\n{command} {version}')


# ~~~ #
def rich_print_available(
        av_dict: dict[str, str | list[str]],
) -> None:
    rp(f'\nhexsum {version}\n', highlight=False)
    hash_table = Table(title='Available Hashes')
    hash_table.add_column(
        header='Hash',
        justify='right',
        style='blue',
        no_wrap=True,
    )
    hash_table.add_column(
        header='Block Size',
        justify='right',
        style='green',
        no_wrap=True,
    )
    hash_table.add_column(
        header='Digest Length',
        justify='right',
        style='green',
        no_wrap=True,
    )
    hash_table.add_column(
        header='Hex Length',
        justify='right',
        style='green',
        no_wrap=True,
    )
    for i in av_dict['hash_list']:
        match i:
            # share has a length option that must be segregated out
            case i if 'shake' in i:
                hash_table.add_row(
                    i,
                    str(object=getattr(hashlib, i)().block_size),
                    '32 (or [-l (int)])',
                    '64 (or 2 * [-s (int)])',
                )
            case _:
                hash_table.add_row(
                    i,
                    str(object=getattr(hashlib, i)().block_size),
                    str(object=getattr(hashlib, i)().digest_size),
                    str(object=2 * getattr(hashlib, i)().digest_size),
                )
    for i in av_dict['xxhash_list']:
        hash_table.add_row(
            i,
            str(object=getattr(xxhash, i)().block_size),
            str(object=getattr(xxhash, i)().digest_size),
            str(object=2 * getattr(xxhash, i)().digest_size),
        )
    hash_table.add_row(
        'blake3',
        str(object=blake3.blake3().block_size),                                         # type: ignore noqa: PGH003
        str(object=blake3.blake3().digest_size),                                        # type: ignore noqa: PGH003
        str(object=2 * blake3.blake3().digest_size),                                    # type: ignore noqa: PGH003
    )
    rp(hash_table)


# ~~~ #     - rich print console output -
def rich_print_final(
        compare: str | None,
        file: Path,
        hash_type_list: list[str],
        hex_values: dict[str, str],
        length: int,
) -> None:
    """Rich print the panel of hex value(s).

    Parameters
    ----------
    compare : str | None
        the optional cli -c hex value to compare to
    file : Path
        the file name that was hashed in Path object format
    hash_type_list : list[str]
        list of hashes to derive values for
    hex_values : dict[str, str]
        the derived hex values with k = hash name and v = hex value
    length : int
        length to use for shake hashes

    Raises
    ------
    typer.Exit
        cleanly exit the program
    """
    # Initial output of the program name and version
    rp(f'\nhexsum {version}\n', highlight=False)

    # uncomment the next line to view all variables for troubleshooting
    # console.log('output_final function', log_locals=True)

    # build hex table for final output
    hex_table = Table(title=f'Hex Value(s) for [green]{file}[/]')
    hex_table.add_column(
        header='Hash',
        justify='center',
        style='blue',
        no_wrap=True,
    )
    hex_table.add_column(
        header='Hex Value',
        justify='left',
        style='bold white',
        no_wrap=False,
        overflow='fold',
    )

    if compare:
        hex_table.add_column(
            header='Origin',
            justify='center',
            style='blue',
            no_wrap=True,
        )
        # short name for hash type
        h: str = hash_type_list[0]
        # short printable hash name including the shake size if applicable
        d: str = f'{h}({length})' if 'shake' in h else h
        hex_table.add_row(
            d,
            hex_values[h],
            'Generated',
        )
        hex_table.add_row(
            d,
            compare,
            'Provided',
        )
        if compare == hex_values[h]:
            hex_table.title = f'[bold]{d}[green] Hex Value for {file} MATCHES![/]'
        else:
            hex_table.title = f'[bold]{d}[red] Hex Value for {file} DOES NOT MATCH!!![/]'
    else:
        for k, v in sorted(hex_values.items()):
            w: list[str] = [f'[blue]{x}[/]' if (i + 1) % 16 == 0 else x for i, x in enumerate(iterable=v)]
            d: str = f'{k}({length})' if 'shake' in k else k
            hex_table.add_row(
                d,
                ''.join(w),
            )

    # rich print and rich panel to display one of the 3 output types
    rp(hex_table)


