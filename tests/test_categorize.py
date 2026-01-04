from bitwarden_folder_organizer_ai.categorize import category_to_label


def test_category_to_label_top_level() -> None:
    assert category_to_label("Tools/Development") == "Tools"


def test_category_to_label_homelab() -> None:
    assert category_to_label("Personal/Homelab") == "Homelab"


def test_category_to_label_dead() -> None:
    assert category_to_label("Dead") == "Dead"
