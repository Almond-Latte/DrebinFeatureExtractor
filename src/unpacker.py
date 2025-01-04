import zipfile
from pathlib import Path


def unpack_sample(tmp_dir: Path, sample_file: Path) -> Path:
    """
    Unpack a sample zip file to a specified temporary directory.

    Args:
        tmp_dir (Path): Path to the temporary directory.
        sample_file (Path): Path to the sample zip file.

    Returns:
        Path: Path to the unpacked location.
    """
    # Define unpack location
    unpack_location = tmp_dir / "unpack"

    # Ensure the unpack location exists
    unpack_location.mkdir(parents=True, exist_ok=True)

    # Unpack the zip file
    try:
        with zipfile.ZipFile(sample_file, "r") as zip_ref:
            zip_ref.extractall(unpack_location)
    except zipfile.BadZipFile as e:
        raise ValueError(f"The file '{sample_file}' is not a valid zip file: {e}")

    return unpack_location
