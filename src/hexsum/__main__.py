#!/usr/bin/env python3
"""hexsum: a python checksum tool using OpenSSL, xxhash, and blake3.

TODO: Add rich progress for file read and hex updates.
TODO: add file size to the output.
TODO: --gnu/--tag
TODO: add length key to blake3 output like shake
TODO: -v read xattr
TODO: -V write xattr
TODO: -Z write checksum file
TODO: -C try to compare against any checksum generated
TODO: --zzz non-rich, traditional output format
TODO: -c read checksum files
TODO: * glob a directory for checksums on files
TODO: -z output
TODO: --ignore-missing
TODO: --quiet
TODO: --status
TODO: --strict
TODO: -w
TODO: possibly add a recursive option with *
TODO: code refactor: all lists into one dict? Pre-build sections into the dict
TODO: code refactor: run all hashes against each processed file chunk so file only read once
TODO: add file read timing
TODO: add individual hex timing
TODO: possibly make a namedtuple class for hash attributes that then get added to main dict
TODO: help cleanup alter <HASH>es into something else; mayber remove " from "-c" switches since auto-colored
"""


import hashlib
from collections.abc import Callable, Generator
from pathlib import Path
from time import perf_counter
from typing import Annotated, Any, Optional

import _file_safely
import _printables
import blake3  # type: ignore noqa: PGH003
import typer
import xxhash
from rich.panel import Panel

# constant for tracking program duration
PROG_TIME_START: float = perf_counter()
READ_FILE_CHUNKS: int = 1_048_576


app: Callable[..., None] = typer.Typer(
    rich_markup_mode='rich',
    add_completion=False,
)

# globally available variables
hash_list: list[str] = sorted(hashlib.algorithms_guaranteed)
xxhash_list: list[str] = sorted(xxhash.algorithms_available)
blake3_list: list[str] = ['blake3']
all_hash_list: list[str] = sorted([*hash_list, *xxhash_list, *blake3_list])


# ~~~ #     - typer callback function -
def callback_ver(ver: bool | None) -> None:
    """Print version and exit.

    Parameters
    ----------
    ver : bool | None
        CLI --version option

    Raises
    ------
    typer.Exit
        cleanly exit program
    """
    if ver:
        _printables.rich_print_version(command='hexsum')
        raise typer.Exit


# ~~~ #     - typer callback function -
def callback_available(
        available: bool | None,
) -> None:
    """Derive and print all available hash types.

    Parameters
    ----------
    available : bool
        CLI Option -a to print all hash types

    Raises
    ------
    typer.Exit
        cleanly exit program
    """
    if available:
        dicty: dict[str, tuple[int, int]] = {}
        av_dict: dict[str, str | list[str]] = {
            'hash_list': hash_list,
            'xxhash_list': xxhash_list,
            'blake3_list': blake3_list,
            'all_hash_list': all_hash_list,
        }
        _printables.rich_print_available(av_dict=av_dict)
        raise typer.Exit


# ~~~ #     - typer callback function -
def callback_hash(
        hash_type: str,
) -> list[str]:
    """Validate the hash requested and return a list with it.

    Parameters
    ----------
    hash_type : str
        CLI -h value

    Returns
    -------
    list
        a list containing all valid requested hash types to run

    Raises
    ------
    typer.Exit
        if no valid hashes to run
    """
    # split the string into list entries
    temp_hash_list:list[str] = hash_type.split(sep=',')
    return_hash_list: list[str] = []
    bad_hash_list: list[str] = []

    # valid hashes into return list, invalid into bad list
    for hash_option in temp_hash_list:
        match hash_option:
            case 'all':
                return all_hash_list
            case hash_option if hash_option in all_hash_list:
                return_hash_list.append(hash_option)
            case _:
                bad_hash_list.append(hash_option)

    # warn if there are bad hashes but don't exit yet
    if len(bad_hash_list) > 0:
        _printables.rp(Panel(
            f'Option "-h {bad_hash_list}" invalid. Must be "-h all" or one or more of {all_hash_list}.',
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
    # exit only if no good hashes to check
    if len(return_hash_list) == 0:
        raise typer.Exit

    return return_hash_list



# ~~~ #     - typer callback function -
def callback_compare(
        compare: str,
) -> str | None:
    """Validate the compare CLI option is a valid hexadecimal number.

    Parameters
    ----------
    compare : str
        CLI Option -c containing the provide hex value

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
            _printables.rp(Panel(
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
        shake_size: int,
) -> str:
    """Read the file, hash it, and return a hex value.

    Parameters
    ----------
    hash_type : str
        the specific hash type to run for this iteration
    file : Path
        the file to hash
    shake_size : int | None
        the size as an int to use if the hash type is shake

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

    incremental_file_bytes: Generator[bytes, Any, None] = _file_safely.read_file_in_chunks(
        file_path=file,
        read_size=READ_FILE_CHUNKS,
    )
    hlib_temp = getattr(ht_base, hash_type)()
    for file_chunk in incremental_file_bytes:
        hlib_temp.update(file_chunk)

    match hash_type:
        case hash_type if 'shake' in hash_type:
            return hlib_temp.hexdigest(shake_size)
        case 'blake3':
            return hlib_temp.hexdigest(length=shake_size)
        case _:
            return hlib_temp.hexdigest()


# ~~~ #     - CLI variables are here in main for typer -
@app.command(rich_help_panel='Standard Options')
def main(
        file: Annotated[Path, typer.Argument(
            default=...,
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            rich_help_panel='[blue]FILE[/]',
            help='The [blue]FILE[/] to hash, or checksum [blue]FILE[/] to check or validate.',
        )],
        a_available: Annotated[Optional[bool] | None, typer.Option(                                       # noqa: UP007
            default='-a',
            is_eager=True,
            rich_help_panel='Hexsum Options',
            callback=callback_available,
            help='Print all available <HASH> types and exit.',
        )] = None,
        c_compare: Annotated[Optional[str] | None, typer.Option(                                          # noqa: UP007
            default='-C',
            show_default=False,
            rich_help_panel='Hexsum Options',
            callback=callback_compare,
            help='Compare to provided checksum; use -h <HASH> to match source algorithm; will attempt to compare '
            'to all with "-h [spring_green3]all[/]"; ex: "-c=bf3ed5f58439bd05"',
        )] = None,
        flag_gnu: Annotated[bool, typer.Option(
            default='--gnu',
            rich_help_panel='Hexsum Options',
            help='Traditional GNU checksum output, "<CHECKSUM> [blue]FILE[/]", with no indication of <HASH> algorithm '
            f'used; use "--zzz" to output this legacy style to console instead of rich {_printables.colorize}d output.',
        )] = False,
        h_hashes: Annotated[str, typer.Option(
            default='-h',
            rich_help_panel='Hexsum Options',
            callback=callback_hash,
            help='<HASH> type to run; "-h=[spring_green3]all[/]" will checksum the [blue]FILE[/] with all <HASH>es; '
                 'use "-a" to view available <HASH>es; use comma delimination with no space for multiple <HASH>es;'
                 'ex: "-h=sha256,blake3" will checksum the [blue]FILE[/] with [spring_green3]sha256[/] and '
                 '[spring_green3]blake3[/].',
        )] = 'sha256',
        s_size: Annotated[int, typer.Option(
            default='-s',
            min=1,
            max=128,
            rich_help_panel='Hexsum Options',
            help='Use with "-h=[spring_green3]shake_128[/]", "-h=[spring_green3]shake_256[/]", and "-h=[spring_green3]'
            'blake3[/]"; otherwise ignored.',
        )] = 32,
        v_validation_read: Annotated[bool, typer.Option(
            default='-v',
            rich_help_panel='Hexsum Options',
            help='Read xattr for saved checksums and validate against live checksum.',
        )] = False,
        v_validation_write: Annotated[bool, typer.Option(
            default='-V',
            rich_help_panel='Hexsum Options',
            help='Write xattr checksums as "user.<HASH>.hash" and "user.<HASH>.date" for future validation.',
        )] = False,
        w_write: Annotated[bool, typer.Option(
            default='-Z',
            rich_help_panel='Hexsum Options',
            help='Write checksum file as "CHECKSUM.<HASH>-[blue]FILE[/] in "--tag" (BSD) style [DEFAULT]; or as '
            '[blue]FILE[/].<HASH> in "--gnu" (GNU) mode.',
        )] = False,
        flag_zzz: Annotated[bool, typer.Option(
            default='--zzz',
            rich_help_panel='Hexsum Options',
            help=f'Print to console in non-{_printables.colorize}d, legacy mode; "--tag" (BSD) style by default, '
            'or "--gnu" (GNU) style.',
        )] = False,
        b_binary: Annotated[bool, typer.Option(
            default='-b',
            show_default=False,
            # hidden=True,  # maybe hide this since it is not used but will not throw error since it exists
            rich_help_panel='Standard Options',
            help='Read in binary mode; legacy switch, ignored as always read binary.',
        )] = True,
        c_check: Annotated[bool, typer.Option(
            default='-c',
            rich_help_panel='Standard Options',
            help='Read checksums from the [blue]FILE[/]s and check them; use "--gnu" to force non-BSD style.',
        )] = False,
        t_text: Annotated[bool, typer.Option(
            default='-t',
            show_default=False,
            # hidden=True,  # maybe hide this since it is not used but will not throw error since it exists
            rich_help_panel='Standard Options',
            help='Read in text mode; legacy switch, ignored as always read binary ("-b").',
        )] = False,
        flag_tag: Annotated[bool, typer.Option(
            default='--tag',
            rich_help_panel='Standard Options',
            help='Create a BSD-style checksum format e.g. "<HASH> ([blue]FILE[/]) = checksum"); use "--zzz" to '
            f'output this legacy style to console instead of rich {_printables.colorize}d output; use "--gnu" to '
            'override this and use GNU style output.',
        )] = True,
        z_nul: Annotated[bool, typer.Option(
            default='-z',
            rich_help_panel='Standard Options',
            help='End each output line with NUL instead of newline, and disable file name escaping.',
        )] = False,
        flag_ignore_missing: Annotated[bool, typer.Option(
            default='--ignore-missing',
            rich_help_panel='[cyan]"-c"[/] Validation Options',
            help='Do not print, report, or exit code fail for missing files.',
        )] = False,
        flag_quiet: Annotated[bool, typer.Option(
            default='--quiet',
            rich_help_panel='[cyan]"-c"[/] Validation Options',
            help='Do not print OK for each successfully verified file.',
        )] = False,
        flag_status: Annotated[bool, typer.Option(
            default='--status',
            rich_help_panel='[cyan]"-c"[/] Validation Options',
            help='Do not print anything; exit codes shows success.',
        )] = False,
        flag_strict: Annotated[bool, typer.Option(
            default='--strict',
            rich_help_panel='[cyan]"-c"[/] Validation Options',
            help='Exit non-zero code for improperly formatted checksum lines.',
        )] = False,
        w_warn: Annotated[bool, typer.Option(
            default='-w',
            rich_help_panel='[cyan]"-c"[/] Validation Options',
            help='Warn about improperly formatted checksum lines.',
        )] = False,
        flag_version: Annotated[Optional[bool] | None, typer.Option(                                    # noqa: UP007
            default='--version',
            is_eager=True,
            rich_help_panel='Standard Options',
            callback=callback_ver,
            help='Print version and exit.',
        )] = None,
) -> None:
    """Print or check various <HASH> algorithmic checksums.

    Use "-a" to view available <HASH>es.
    """
    # guard against mutually exclusive "-h all" and "-c <hex value>"
    if c_compare and len(h_hashes) > 1:
        _printables.rp(Panel(
            "cannot combine '-c' and '-h all'.",
            title='[bold]Error[/]',
            title_align='left',
            border_style='red',
            highlight=True,
            ),
        )
        raise typer.Exit

    # iterate through requested hash or hashes deriving hex values
    hex_values: dict[str, str] = {h: render_hex(hash_type=h, file=file, shake_size=s_size) for h in h_hashes}

    # call the fancy output function
    _printables.rich_print_final(
        compare=c_compare,
        file=file,
        hash_type_list=h_hashes,                                                                # type: ignore PGH003
        hex_values=hex_values,
        length=s_size,
    )

    # exit the app
    prog_time_total: float = perf_counter() - PROG_TIME_START
    _printables.rp(Panel(
        f':glowing_star: Complete :glowing_star: ([green]{prog_time_total:.4f}[/]s)',
        border_style='green',
        highlight=False,
        ),
    )
    raise typer.Exit


# ~~~ #
if __name__ == '__main__':

    # use typer to build cli arguments off main variables
    app()
