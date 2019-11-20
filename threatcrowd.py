import modules.threatcrowd as threatcrowd


def main():
    threatcrowdip = threatcrowd.ThreatcrowdScan("167.88.206.88", 1)
    threatcrowdip.run()


if __name__ == '__main__':
    main()
