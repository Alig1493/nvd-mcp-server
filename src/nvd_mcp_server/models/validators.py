import enum
import logging
import re

logger = logging.getLogger("__name__")


class VectorStringType(enum.StrEnum):
    V2 = enum.auto()
    V3 = enum.auto()
    V31 = enum.auto()
    V4 = enum.auto()


def validate_vector_string(
    vector_string: str, vector_string_type: VectorStringType
) -> str:
    pattern = None
    match vector_string_type:
        case VectorStringType.V2:
            pattern = (
                r"^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP"
                r":(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:"
                r"(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$"
            )
        case VectorStringType.V3:
            pattern = (
                r"^CVSS:3[.]0/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|"
                r"[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|"
                r"MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|"
                r"M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|"
                r"[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|"
                r"MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|"
                r"M[CIA]:[XNLH])$"
            )
        case VectorStringType.V31:
            pattern = (
                r"^CVSS:3[.]1/((AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|"
                r"RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)"
                r"*(AV:[NALP]|AC:[LH]|PR:[NLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:"
                r"[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$"
            )
        case VectorStringType.V4:
            pattern = (
                r"^CVSS:4[.]0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/"
                r"VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN]"
                r"(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?"
                r"(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?"
                r"(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?"
                r"(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?"
                r"(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?"
                r"(\/U:(X|Clear|Green|Amber|Red))?$"
            )
        case _:
            raise ValueError(
                f"Invalid vector string type of value {vector_string_type} provided."
            )


    if not re.match(pattern, vector_string):
        logger.error(
            f"Invalid vector string {vector_string} "
            f"provided for type: {vector_string_type}."
        )
        raise ValueError(
            f"Invalid vector string {vector_string} "
            f"provided for type: {vector_string_type}."
        )
    return vector_string
