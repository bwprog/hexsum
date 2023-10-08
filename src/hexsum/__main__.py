#!/usr/bin/env python3
"""hexsum: A cli tool to use python hashlib wrapped around OpenSSL to generate hex sums."""

__author__ = 'Brandon Wells'
__email__ = 'b.w.prog@outlook.com'
__copyright__ = '© 2023 Brandon Wells'
__license__ = 'GPL3+'
__status__ = 'Development'
__update__ = '2023.10.08'
__version__ = '0.9.2'


import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.traceback import install

# rich enhancements: console output | install provides traceback | rich print (rp)
console = Console()
install()
rp: Callable[..., None] = console.print

# globally available variables
ver: str = f'hexsum [green]-[/] {__version__} [green]({__update__})[/]'
hash_list: list[str] = sorted(hashlib.algorithms_guaranteed)


# ~~~ #     - typer callback function -
def callback_version(version: bool) -> None:
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
def callback_available(available: bool) -> None:
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
            style='#cb4b16',
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
                case 'shake':
                    hash_table.add_row(
                        i,
                        str(getattr(hashlib, i)().block_size),
                        '32 (or -l)',
                        '64 (or 2 * -l)',
                    )
                case _:
                    hash_table.add_row(
                        i,
                        str(getattr(hashlib, i)().block_size),
                        str(getattr(hashlib, i)().digest_size),
                        str(2 * getattr(hashlib, i)().digest_size),
                    )

        rp(hash_table)
        raise typer.Exit


# ~~~ #     - typer callback function -
def callback_length(length: int) -> int:
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
def callback_hash(hash_type: str) -> list[str]:
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
            return hash_list
        case hash_type if hash_type in hash_list:
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
def callback_compare(compare: str) -> str | None:
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
def render_hex(hex_dict: dict, hash_value) -> str:
    """Read the file, hash it, and return a hex value.

    Parameters
    ----------
    hex_dict : dict
        main dictionary containing all the variables
    hash_value : bool
        the specific hash type to run for this iteration

    Returns
    -------
    str
        the hex value of the requested hash type

    Raises
    ------
    typer.Exit
        if the file cannot be read (OSError)
    """
    try:
        with Path.open(hex_dict['file'], mode='rb') as f:
            hashed_value = hex_dict['hex_function'][hash_value](f.read())
            if 'shake' in hash_value:
                return hashed_value.hexdigest(hex_dict['length'])
            else:
                return hashed_value.hexdigest()

    except OSError as e:
        rp(Panel(
            f'cannot read file: {hex_dict["file"]}\n{e}.',
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
        raise typer.Exit from OSError


# ~~~ #     - rich print console output -
def output_final(hex_dict: dict) -> None:
    """Rich print the panel of hex value(s).

    Parameters
    ----------
    hex_dict : dict
        main dictionary containing all the variables

    Raises
    ------
    typer.Exit
        cleanly exit the program
    """
    # Initial output of the program name and version
    rp(f'\n{ver}\n', highlight=False)
    # uncomment the next line to view all variables for troubleshooting
    # console.log('output_final function', log_locals=True)

    # rich panel attributes
    hex_panel_content: str = ''
    hex_panel_title: str = ''
    hex_panel_border_style: str = ''

    # 3 print options: compare | all | regular
    if hex_dict['compare']:
        h = hex_dict['hash_type_list'][0]
        # h_d (hash display) used to add the length to the shake hash display
        h_d = f'{h}({hex_dict["length"]})' if 'shake' in h else h
        hex_panel_content = f'Generated: {hex_dict["hex_value"][h]}\n'
        hex_panel_content += f'Compared:  {hex_dict["compare"]}'
        # validate hex values match and print accordingly
        if hex_dict['compare'] == hex_dict['hex_value'][h]:
            hex_panel_title = f'[bold]{h_d}[/] Hex Value for {hex_dict["file"]}'
            hex_panel_title += ' [bold]MATCH![/]'
            hex_panel_border_style = 'green'
        else:
            hex_panel_title = f'[bold]{h_d}[/] Hex Value for {hex_dict["file"]}'
            hex_panel_title += ' [bold]DO NOT MATCH!!![/]'
            hex_panel_border_style = 'red'
    elif len(hex_dict['hash_type_list']) > 1:
        hex_panel_title = f'Hex Values for {hex_dict["file"]}'
        hex_panel_border_style = 'green'
        hex_panel_content = '[bold blue]hash[/]\t\t[bold green]Value[/]\n'
        for i, h in enumerate(hex_dict['hash_type_list']):
            # h_d (hash display) used to add the length to the shake hash display
            h_d = f'{h}({hex_dict["length"]})' if 'shake' in h else h
            hex_panel_content += f'[bold]{h_d:<16s}[/]{hex_dict["hex_value"][h]}'
            hex_panel_content += '\n' if i < (len(hex_dict['hash_type_list']) - 1) else ''
    else:
        h = hex_dict['hash_type_list'][0]
        # h_d (hash display) used to add the length to the shake hash display
        h_d = f'{h}({hex_dict["length"]})' if 'shake' in h else h
        hex_panel_title = f'[bold]{h_d}[/] Hex Value for {hex_dict["file"]}'
        hex_panel_border_style = 'green'
        hex_panel_content = hex_dict['hex_value'][h]

    # rich print and rich panel to display one of the 3 output types
    rp(Panel(hex_panel_content, title=hex_panel_title, title_align='left',
             border_style=hex_panel_border_style, highlight=True))

    raise typer.Exit


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

    # create hashing and hex dictionary
    hex_dict = {
        'file': file,
        'file_size': Path(file).stat().st_size,
        'hash_type_list': hash_type_list,
        'length': length,
        'compare': compare,
        'hex_function': {h: getattr(hashlib, h) for h in hash_type_list},
        'hex_value': {},
    }

    # iterate through requested hash or hashes deriving hex values
    for hash_type in hex_dict['hash_type_list']:
        hex_dict['hex_value'][hash_type] = render_hex(hex_dict=hex_dict,
                                                      hash_value=hash_type)

    # call the fancy output function
    output_final(hex_dict=hex_dict)


# ~~~ #
if __name__ == '__main__':

    # use typer to build cli arguments off main variables
    typer.run(main)
