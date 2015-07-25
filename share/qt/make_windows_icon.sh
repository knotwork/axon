#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/novacoin.ico

convert ../../src/qt/res/icons/axiom-16.png ../../src/qt/res/icons/axiom-32.png ../../src/qt/res/icons/axiom-48.png ${ICON_DST}
