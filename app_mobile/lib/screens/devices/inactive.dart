import 'package:homeflow/models/device.dart';
import 'package:homeflow/utils/misc.dart';
import 'package:homeflow/shared/help_screen.dart';
import 'package:flutter/material.dart';
import 'package:homeflow/shared/constants.dart';

class InactiveDevice extends StatelessWidget {
  final FirebaseDevice firebaseDevice;

  InactiveDevice(this.firebaseDevice);

  @override
  Widget build(BuildContext context) {
    return ConstrainedBox(
        constraints: BoxConstraints(minHeight: CardMinHeight),
        child: Card(
            child: InkWell(
          splashColor: Colors.blue.withAlpha(30),
          onTap: () {
            print('Card tapped.');
          },
          child: Container(
              child: Column(
            children: [
              SizedBox(
                height: 5,
              ),
              Text(upperFirstCharacter(firebaseDevice.type),
                  style: TextStyle(fontSize: 24)),
              Divider(
                indent: 20,
                endIndent: 20,
                thickness: 1,
              ),
              Column(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(
                      Icons.warning,
                      size: 48,
                    ),
                    Text("Device is not active",
                        style: TextStyle(fontSize: 17)),
                    GestureDetector(
                      child: Text(
                        "Need help? Click here",
                        style: TextStyle(fontSize: 13, color: LayoutBlueColor1),
                      ),
                      onTap: () {
                        print("Tap need help");
                        Navigator.push(
                            context,
                            MaterialPageRoute(
                                builder: (context) => HelpScreen()));
                      },
                    )
                  ]),
            ],
          )),
        )));
  }
}
