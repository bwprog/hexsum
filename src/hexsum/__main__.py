#!/usr/bin/env python3
"""hexsum: A cli tool to use python hashlib wrapped around OpenSSL to generate hex sums.

TODO: Guard against memory consumption by cycling through file read and hex update.
TODO: Add rich progress for file read and hex updates.
TODO: add file size to the output.
"""

__author__ = 'Brandon Wells'
__email__ = 'b.w.prog@outlook.com'
__copyright__ = '© 2023 Brandon Wells'
__license__ = 'GPL3+'
__status__ = 'Development'
__update__ = '2023.10.14'
__version__ = '0.9.5'


import hashlib
from collections.abc import Callable
from pathlib import Path
from time import perf_counter
from typing import Annotated, Any, Optional

import blake3  # type: ignore noqa: PGH003
import typer
import xxhash
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.traceback import install

# constant for tracking program duration
PROG_TIME_START: float = perf_counter()


# rich enhancements: console output | install provides traceback | rich print (rp)
console = Console()
install()
rp: Callable[..., None] = console.print

# globally available variables
ver: str = f'hexsum [green]-[/] {__version__} [green]({__update__})[/]'
hash_list: list[str] = sorted(hashlib.algorithms_guaranteed)
xxhash_list: list[str] = sorted(xxhash.algorithms_available)
blake3_list: list[str] = ['blake3']

# ~~~ #     - typer callback function -
def callback_version(
        version: bool,
) -> None:
    """Print version and exit.

    Parameters
    ----------
    version : bool
        CLI option -v/--version to print program version

    Raises
    ------
    typer.Exit
        normal cleanup and exit after completing request
    """
    if version:
        rp(f'\n{ver}\n', highlight=False)
        raise typer.Exit


# ~~~ #     - typer callback function -
def callback_available(
        available: bool,
) -> None:
    """Derive and print all available hash types.

    Parameters
    ----------
    available : bool
        CLI Option -a/--available to print all hash types

    Raises
    ------
    typer.Exit
        normal cleanup exit after completing request
    """
    if available:
        rp(f'\n{ver}\n', highlight=False)
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
        for i in hash_list:
            match i:
                # share has a length option that must be segregated out
                case i if 'shake' in i:
                    hash_table.add_row(
                        i,
                        str(object=getattr(hashlib, i)().block_size),
                        '32 (or [-l (int)])',
                        '64 (or 2 * [-l (int)])',
                    )
                case _:
                    hash_table.add_row(
                        i,
                        str(object=getattr(hashlib, i)().block_size),
                        str(object=getattr(hashlib, i)().digest_size),
                        str(object=2 * getattr(hashlib, i)().digest_size),
                    )
        for i in xxhash_list:
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
        raise typer.Exit


# ~~~ #     - typer callback function -
def callback_length(
        length: int,
) -> int:
    """Validate the CLI length Option.

    Parameters
    ----------
    length : int
        CLI Option -l/--length to use with shake hash

    Returns
    -------
    int
        the same length as requested

    Raises
    ------
    typer.Exit
        invalid CLI Option value for length
    """
    match length:
        case length if 1 > length > 128:                                                                # noqa: PLR2004
            rp(Panel(
                f'Option "-l {length}" invalid. Length must be between (and including) 1 and 128.',
                title='[bold]Error[/]',
                title_align='left',
                border_style='red',
                highlight=True,
                ),
            )
            raise typer.Exit
        case _:
            return length


# ~~~ #     - typer callback function -
def callback_hash(
        hash_type: str,
) -> list[str]:
    """Validate the hash requested and return a list with it.

    Parameters
    ----------
    hash_type : str
        CLI Option -h/--hash to specify the hash type to run (or all)

    Returns
    -------
    list
        a list containing all requested hash types to run

    Raises
    ------
    typer.Exit
        Invalid CLI Option value for hash type
    """
    match hash_type:
        case 'all':
            return [*hash_list, *xxhash_list, *blake3_list]
        case hash_type if hash_type in hash_list:
            return [hash_type]
        case hash_type if hash_type in xxhash_list:
            return [hash_type]
        case hash_type if hash_type in blake3_list:
            return [hash_type]
        case _:
            rp(Panel(
                f'Option "-h {hash_type}" invalid. Must be "-h all" or one of -h {hash_list}.',
                title='[bold]Error[/]',
                title_align='left',
                border_style='red',
                highlight=True,
                ),
            )
            raise typer.Exit


# ~~~ #     - typer callback function -
def callback_compare(
        compare: str,
) -> str | None:
    """Validate the compare CLI option is a valid hexadecimal number.

    Parameters
    ----------
    compare : str
        CLI Option -c/--compare containing the provide hex value

    Returns
    -------
    Optional[str]
        the compare string if valid

    Raises
    ------
    typer.Exit
        ValueError if the number is invalid
    """
    if compare:
        try:
            # guard against an invalid hex value by ensuring the string entered is valid hex
            # do a straight convert of str to int using base 16 (hex); don't need value
            int(compare, base=16)
        except ValueError:
            rp(Panel(
                f'"-c {compare}" is an invalid hexadecimal number.',
                title='[bold]Error[/]',
                title_align='left',
                border_style='red',
                highlight=True,
                ),
            )
            raise typer.Exit from ValueError
        return compare
    else:                                                                                               # noqa: RET505
        return None


# ~~~ #     - the hashlib function to derive hex values -
def render_hex(
        hash_type: str,
        file: Path,
        length: int,
) -> str:
    """Read the file, hash it, and return a hex value.

    Parameters
    ----------
    hash_type : str
        the specific hash type to run for this iteration
    file : Path
        the file to hash
    length : int | None
        the length as an int to use if the hash type is shake

    Returns
    -------
    str
        the hex value of the requested hash type

    Raises
    ------
    typer.Exit
        if the file cannot be read (OSError)
    """
    ht_base: Any = ''
    if hash_type in hash_list:
        ht_base = hashlib
    elif hash_type in xxhash_list:
        ht_base = xxhash
    elif hash_type in blake3_list:
        ht_base = blake3
    try:
        with Path.open(file, mode='rb') as f:
            hashed_value: Any = getattr(ht_base, hash_type)(f.read())
            match hash_type:
                case hash_type if 'shake' in hash_type:
                    return hashed_value.hexdigest(length)                                       # type: ignore PGH003
                case _:
                    return hashed_value.hexdigest()

    except OSError as e:
        rp(Panel(
            f'cannot read file: {file}\n{e}.',
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
        raise typer.Exit from OSError


# ~~~ #     - rich print console output -
def output_final(
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
        the optional cli --compare/-c hex value to compare to
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
    rp(f'\n{ver}\n', highlight=False)

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
        # short printable hash name including the shake length if applicable
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
        for k, v in hex_values.items():
            d: str = f'{k}({length})' if 'shake' in k else k
            hex_table.add_row(
                d,
                v,
            )

    # rich print and rich panel to display one of the 3 output types
    rp(hex_table)


# ~~~ #     - CLI variables are here in main for typer -
def main(
        file: Annotated[Path, typer.Argument(
            ...,
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help='The file to generate hexsum for',
        )],
        hash_type_list: Annotated[str, typer.Option(
            '--hash',
            '-h',
            callback=callback_hash,
            help='Hash type to run | --hash all  will run all hashes | --hash all  cannot be combined with --compare',
        )] = 'sha256',
        length: Annotated[int, typer.Option(
            '--length',
            '-l',
             callback=callback_length,
            help='For shake hash [1-128]',
        )] = 32,
        compare: Annotated[Optional[str] | None, typer.Option(                                          # noqa: UP007
            '--compare',
            '-c',
            callback=callback_compare,
            help='Compare to hash from source | cannot be combined with --hash all',
        )] = None,
        available: Annotated[Optional[bool] | None, typer.Option(                                       # noqa: UP007
            '--available',
            '-a',
            is_eager=True,
            callback=callback_available,
            help='Print all available hash types and exit.',
        )] = None,
        version: Annotated[Optional[bool] | None, typer.Option(                                         # noqa: UP007
            '--version',
            '-v',
            is_eager=True,
            callback=callback_version,
            help='Print version and exit.',
        )] = None,
) -> None:
    """Calculate hexsum hash codes for files."""
    # guard against mutually exclusive "-h all" and "-c <hex value>"
    if compare and len(hash_type_list) > 1:
        rp(Panel(
            "cannot combine '-c' and '-h all'.",
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
        raise typer.Exit

    # iterate through requested hash or hashes deriving hex values
    hex_values: dict[str, str] = {h: render_hex(hash_type=h, file=file, length=length) for h in hash_type_list}

    # call the fancy output function
    output_final(
        compare=compare,
        file=file,
        hash_type_list=hash_type_list,                                                          # type: ignore PGH003
        hex_values=hex_values,
        length=length,
    )

    # exit the app
    prog_time_total: float = perf_counter() - PROG_TIME_START
    rp(Panel(
        f':glowing_star: Complete :glowing_star: ([green]{prog_time_total:.4f}[/]s)',
        border_style='green',
        highlight=False,
        ),
    )
    raise typer.Exit


# ~~~ #
if __name__ == '__main__':

    # use typer to build cli arguments off main variables
    typer.run(function=main)
