# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


import shieldyapi


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app_guid = "76934b5e-2191-47e2-88a2-a05000a3bbf9"
    version = "1.0"
    app_salt = "6166edbd36aec11af66e722e40baa2c7645387f28efe4e60abcc454723f6439e"

    api = shieldyapi.ShieldyAPI()

    if not api.init(app_guid, version, app_salt):
        print("Failed to initialize, last error: " + str(api.get_last_error()))
        exit(1)

    print("Init success")

    if not api.login("username123", "tajnehaslo"):
        print("Failed to login")
        exit(1)

    print("Login success, welcome " + api.get_user_property("username"))

    print("Last error: " + str(api.get_last_error()))
    print("Variable test: " + api.get_variable("PerApp"))
    print("Deobfuscated variable test: " + api.deobfuscate_string("qeOIDvtmi0Qd71WRFHUlMg==", 10))

    print("Downloading file...")
    file = api.download_file("ScoopyNG.zip")
    print("File size: " + str(len(file)))

    with open("ScoopyNG.zip", "wb") as f:
        f.write(file)

    print("Done")
