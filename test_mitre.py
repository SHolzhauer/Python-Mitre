import unittest
from mitre import Attck, Tactic, Technique


class MyTestCase(unittest.TestCase):

    def test_valid_tactics(self):
        A = Attck()
        tactic = A.tactic("TA0001")
        self.assertEqual(tactic.name, "Initial Access")
        self.assertEqual(tactic.created, "2020-10-17")
        self.assertEqual(tactic.techniques, [
                    "T1189",
                    "T1190",
                    "T1133",
                    "T1200",
                    "T1566",
                    "T1566.001",
                    "T1566.002",
                    "T1566.003",
                    "T1091",
                    "T1195",
                    "T1195.001",
                    "T1195.002",
                    "T1195.003",
                    "T1199",
                    "T1078",
                    "T1078.001",
                    "T1078.002",
                    "T1078.003",
                    "T1078.004"
                ])
        for tech in tactic.techniques:
            self.assertIn(tech, A._techniques)

    def test_techniques(self):
        A = Attck()
        techniques = []
        for tac in A._tactics:
            for tech in A._tactics[tac]["techniques"]:
                if tech not in techniques:
                    techniques.append(tech)

        # Test all the existing techniques
        for tech in techniques:
            technique = A.technique(tech)
            if "." in tech:
                main = tech.split(".")[0]
                sub = tech.split(".")[1]
                self.assertEqual(technique.url,
                                 "https://attack.mitre.org/versions/{}/techniques/{}/{}/".format(A.version, main, sub))
            else:
                self.assertEqual(technique.url, "https://attack.mitre.org/versions/{}/techniques/{}/".format(A.version, tech))


    def test_techniques_exist(self):
        A = Attck()
        for tac in A._tactics:
            t = A.tactic(tac)
            for tech in t.techniques:
                self.assertIn(tech, A._techniques)

    def test_procedures_exist(self):
        A = Attck()
        for tac in A._tactics:
            t = A.tactic(tac)
            for tech in t.techniques:
                for proc in A._techniques[tech]["procedures"]:
                    self.assertIn(proc, A._procedures)

    def test_mitigations_exist(self):
        A = Attck()
        techniques = []
        for tac in A._tactics:
            t = A.tactic(tac)
            for tech in t.techniques:
                for mit in A._techniques[tech]["mitigations"]:
                    self.assertIn(mit, A._mitigations)


if __name__ == '__main__':
    unittest.main()
