#!/usr/bin/env python3
"""
hexsum: a cli tool to use python's hashlib wrapped around OpenSSL to generate
        any available hash within the lib against any file. This makes use of
        rich for color, panel, and table output, and typer for CLI arguments.
TODO: rich spinner while waiting for large files (>200MB)
TODO: add testing
"""

__author__ = 'Brandon Wells'
__maintainer__ = 'Brandon Wells'
__email__ = 'b.w.prog@outlook.com'
__copyright__ = '© 2023 Brandon Wells'
__license__ = 'GPL3+'
__status__ = 'Development'
__update__ = '2023.02.01'
__version__ = '0.9.0'


import hashlib
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.traceback import install
import typer


# rich enhancements: console output | install provides traceback | rich print (rp)
console = Console()
install()
rp = console.print

# globally available variables
ver = f'pyhash {__version__} ({__update__})'
hash_list = sorted(hashlib.algorithms_guaranteed)


# ~~~ #     - typer callback function -
def callback_version(version: bool) -> None:
    """Print version and exit.

    Args:
        version (bool): CLI Option to print program version

    Raises:
        typer.Exit: normal cleanup exit after completing request
    """
    if version:
        rp(f'\n{ver}\n', style='bold blue', highlight=False)
        raise typer.Exit()


# ~~~ #     - typer callback function -
def callback_available(available: bool) -> None:
    """Derive and print all available hash types.

    Args:
        available (bool): CLI Option to print all hash types

    Raises:
        typer.Exit: normal cleanup exit after completing request
    """
    if available:
        rp(f'\n{ver}\n', style='bold blue', highlight=False)
        hash_table = Table(title='Available Hashes')
        hash_table.add_column('Hash', justify='right', style='#cb4b16', no_wrap=True)
        hash_table.add_column('Block Size', justify='right', style='green', no_wrap=True)
        hash_table.add_column('Digest Length', justify='right', style='green', no_wrap=True)
        hash_table.add_column('Hex Length', justify='right', style='green', no_wrap=True)
        for i in hash_list:
            if 'shake' not in i:
                hash_table.add_row(i, str(getattr(hashlib, i)().block_size),
                                   str(getattr(hashlib, i)().digest_size),
                                   str(2 * getattr(hashlib, i)().digest_size))
            else:
                hash_table.add_row(i, str(getattr(hashlib, i)().block_size),
                                   '32 (or -l)', '64 (or 2 * -l)')
        rp(hash_table)
        raise typer.Exit()


# ~~~ #     - typer callback function -
def callback_length(length: int) -> int:
    """A typer callback to validate the length CLI Option.

    Args:
        length (int): the CLI specified Option

    Raises:
        typer.Exit: invalid CLI Option value for length

    Returns:
        int: the same length as requested
    """
    if length < 1 or length > 128:
        rp(Panel(f"Option '-l {length}' invalid. Length must be between (and including)"
                 ' 1 and 128.', title='[bold]Error[/]', title_align='left', border_style='red',
                 highlight=True))
        raise typer.Exit()
    else:
        return length


# ~~~ #     - typer callback function -
def callback_hash(hash_type: str) -> list:
    """A typer callback to validate the hash requested and return a list with it.

    Args:
        hash_type (str): the hash type requested

    Raises:
        typer.Exit: Invalid CLI Option value for hash type

    Returns:
        list: a list containing all requested hash types to run
    """
    if hash_type == 'all':
        return hash_list
    elif hash_type in hash_list:
        return [hash_type,]
    else:
        rp(Panel(f"Option '-h {hash_type}' invalid. Must be '-h all' or -h {hash_list}.",
                 title='[bold]Error[/]', title_align='left', border_style='red', highlight=True))
        raise typer.Exit()


# ~~~ #     - typer callback function -
def callback_compare(compare: str) -> Optional[str]:
    """Validate the compare CLI number is a valid hexadecimal number.

    Args:
        compare (str): the CLI specified hex value

    Raises:
        typer.Exit: ValueError if the number is invalid

    Returns:
        str: the compare string if valid
    """
    if compare:
        try:
            # do a straight convert of str to int using base 16 (hex)
            int(compare, 16)
            return compare
        except ValueError:
            rp(Panel(f"'-c {compare}' is an invalid hexadecimal number.", title='[bold]Error[/]',
                     title_align='left', border_style='red', highlight=True))
            raise typer.Exit() from ValueError
    else:
        return None


# ~~~ #     - the hashlib function to derive hex values -
def render_hex(hex_dict: dict, hash_value) -> str:
    """Read the file, hash it, and return a hex value.

    Args:
        hex_dict (dict): main dictionary containing all the variables
        hash_value (bool): the specific hash type to run for this iteration

    Raises:
        typer.Exit: if the file cannot be read (OSError)

    Returns:
        str: the hex value of the requested hash type
    """
    try:
        with open(hex_dict['file'], 'rb') as f:
            hashed_value = hex_dict['hex_function'][hash_value](f.read())
            if 'shake' in hash_value:
                return hashed_value.hexdigest(hex_dict['length'])
            else:
                return hashed_value.hexdigest()

    except OSError as e:
        rp(Panel(f"cannot read file: {hex_dict['file']}\n{e}.", title='[bold]Error[/]',
                 title_align='left', border_style='red', highlight=True))
        raise typer.Exit() from OSError


# ~~~ #     - rich print console output -
def output_final(hex_dict: dict) -> None:
    """Using rich print and panel to output the hex value(s) in a nice format

    Args:
        hex_dict (dict): main dictionary containing all the variables

    Returns:
        _type_: None
    """
    rp(f'\n{ver}\n', style='bold blue', highlight=False)
    # uncomment the next line to view all variables for troubleshooting
    # console.log('output_final function', log_locals=True)

    # rich panel attributes
    hex_panel_content, hex_panel_title, hex_panel_border_style = '', '', ''

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
    return None


# ~~~ #     - CLI variables are here in main for typer -
def main(
    file: Path = typer.Argument(..., exists=True),
    hash_type_list: Optional[str] = typer.Option(
        'sha256', '--hash', '-h', callback=callback_hash,
        help='Hash type to run | use "all" to run all hashes'
    ),
    length: Optional[int] = typer.Option(
        32, '--length', '-l', help='For shake hash [1-128]', callback=callback_length
    ),
    compare: Optional[str] = typer.Option(
        None, '--compare', '-c', help='Compare to hash from source',
        callback=callback_compare
    ),
    available: Optional[bool] = typer.Option(
        None, '--available', '-a', help='Print all available hash types and exit.',
        callback=callback_available, is_eager=True
    ),
    version: Optional[bool] = typer.Option(
        None, '--version', '-v', help='Print version and exit.',
        callback=callback_version, is_eager=True
    )
) -> None:
    """
    Calculate hash codes for files.
    """
    # guard against mutually exclusive "-h all" and "-c <hex value>"
    if compare and len(hash_type_list) > 1:
        rp(Panel("cannot combine '-c' and '-h all'.", title='[bold]Error[/]',
                 title_align='left', border_style='red', highlight=True))
        raise typer.Exit()

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
if __name__ == "__main__":

    # use typer to build cli arguments off main variables
    typer.run(main)
