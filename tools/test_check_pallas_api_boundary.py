"""Regression checks for the Pallas public/secret API boundary gate."""

import unittest

from check_pallas_api_boundary import function_body, require


class ConditionalCompilation(unittest.TestCase):
    def test_unconditional_body_is_checked(self):
        body = function_body("void sign(void) {\n  pallas_ct_add_mod_q();\n}\n",
                             "sign")
        require(body, "pallas_ct_add_mod_q", "sign")

    def test_required_token_in_dead_branch_cannot_pass(self):
        source = ("void sign(void) {\n#if 0\n  pallas_ct_add_mod_q();\n"
                  "#endif\n  pallas_add_mod_q();\n}\n")
        with self.assertRaisesRegex(AssertionError, "preprocessor conditionals"):
            function_body(source, "sign")

    def test_every_conditional_directive_is_refused(self):
        for directive in ("#if X", "# if X", "#ifdef X", "#ifndef X",
                          "#elif X", "#else", "  #endif"):
            with self.subTest(directive=directive):
                source = "void f(void) {\n" + directive + "\n}\n"
                with self.assertRaises(AssertionError):
                    function_body(source, "f")

    def test_non_conditional_directive_is_allowed(self):
        body = function_body("void f(void) {\n#define N 2\n  g(N);\n}\n", "f")
        require(body, "g(N)", "f")


class DefinitionAnchoring(unittest.TestCase):
    def test_caller_cannot_stand_in_for_the_definition(self):
        source = ("void caller(void) {\n  if (sign(x)) {\n    pallas_ct_add_mod_q();\n"
                  "  }\n}\n\nstatic bool sign(int x) {\n  pallas_add_mod_q();\n}\n")
        body = function_body(source, "sign")
        self.assertIn("pallas_add_mod_q", body)
        self.assertNotIn("pallas_ct_add_mod_q", body)

    def test_return_type_on_its_own_line(self):
        body = function_body("static bool\nsign(int x,\n     int y) {\n  g();\n}\n",
                             "sign")
        require(body, "g()", "sign")

    def test_call_only_is_not_a_definition(self):
        with self.assertRaisesRegex(AssertionError, "function not found"):
            function_body("void f(void) {\n  if (sign(x)) {\n  }\n}\n", "sign")


if __name__ == "__main__":
    unittest.main()
