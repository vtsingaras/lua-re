"""Soundness checks for inferred direct calls at control-flow joins."""
import unittest
from lua_re_ida.analysis import analyze_function
from lua_re_ida.bytecode import parse, Upvalue
from test_bytecode import fixture, abc, abx, sj


def model(words, children=()):
    p = parse(fixture(words, children=children)).root
    for child in p.children:
        child.upvalues = []
    return p


class AnalysisTests(unittest.TestCase):
    def test_matching_closures_survive_join(self):
        p = model([abc('TEST', a=1), sj(2), abx('CLOSURE'), sj(1),
                   abx('CLOSURE'), abc('CALL', b=1, c=1), abc('RETURN0')],
                  children=([abc('RETURN0')],))
        calls, _ = analyze_function(p)
        self.assertEqual(calls[0].callee, p.children[0].code_offset)

    def test_conflicting_closures_become_unknown(self):
        p = model([abc('TEST', a=1), sj(2), abx('CLOSURE'), sj(1),
                   abx('CLOSURE', bx=1), abc('CALL', b=1, c=1), abc('RETURN0')],
                  children=([abc('RETURN0')], [abc('RETURN0')]))
        calls, _ = analyze_function(p)
        self.assertEqual(calls[0].callee, -1)

    def test_unreachable_closure_is_not_a_call(self):
        p = model([sj(2), abx('CLOSURE'), abc('CALL', b=1, c=1), abc('RETURN0')],
                  children=([abc('RETURN0')],))
        self.assertEqual(analyze_function(p)[0], [])

    def test_testset_preserves_old_register_on_skip(self):
        p = model([abx('CLOSURE'), abx('CLOSURE', a=1, bx=1),
                   abc('TESTSET', b=1), sj(0), abc('CALL', b=1, c=1), abc('RETURN0')],
                  children=([abc('RETURN0')], [abc('RETURN0')]))
        self.assertEqual(analyze_function(p)[0][0].callee, -1)

    def test_implicit_call_invalidates_mutable_capture(self):
        p = model([abx('CLOSURE'), abc('LEN', a=2, b=1),
                   abc('CALL', b=1, c=1), abc('RETURN0')], children=([abc('RETURN0')],))
        p.children[0].upvalues = [Upvalue(1, 0, 0, 0)]
        self.assertEqual(analyze_function(p)[0][0].callee, -1)

    def test_generic_loop_preserves_iterator(self):
        p = model([abx('CLOSURE'), abx('TFORPREP', bx=0),
                   abc('TFORCALL', c=1), abx('TFORLOOP', bx=2), abc('RETURN0')],
                  children=([abc('RETURN0')],))
        p.children[0].upvalues = []
        self.assertEqual(analyze_function(p)[0][0].callee, p.children[0].code_offset)
