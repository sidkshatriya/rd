# Credits

The `rd` project would not have been possible without the work done in the [rr-debugger/rr](https://github.com/rr-debugger/rr) project. Many human-years of development effort have gone into making `rr` the truly amazing piece of software that it is.

The `rd` project is grateful to all the contributors of the `rr-debugger/rr` project.

The `rd` project was ported over from the `rr` codebase as of commit [`abd344288878c9b4046e0b8664927992947a46eb`](https://github.com/rr-debugger/rr/commits/abd344288878c9b4046e0b8664927992947a46eb). 

The following are the contributors to the `rr` project till commit `abd344288878c9b4046e0b8664927992947a46eb` found via the following invocation:

```bash
$ git log abd344288878c9b4046e0b8664927992947a46eb --format="%an" | sort | uniq -c | sort -g -r
```
(_Listed in descending order by the number of commits made in the rr git repo_)
```
   3107 Robert O'Callahan
    875 Chris Jones
    233 Nathan Froyd
    149 Keno Fischer
    106 Kyle Huey
    101 anoll
     52 nimrodpar
     31 Thomas Anderegg
     21 rocallahan
     19 Brooks Moses
     13 Steve Fink
     13 David Reiss
     10 Ted Mielczarek
     10 Benoit Girard
      9 Andreas Gal
      8 Yichao Yu
      6 Rolf Eike Beer
      6 Rafael Ávila de Espíndola
      6 Juraj Oršulić
      6 Davide Italiano
      6 Daniel Näslund
      5 Tom Tromey
      5 Stephen Kitt
      5 Mike Hommey
      4 tpltnt
      4 Tobias Bosch
      4 Qian Hong
      4 passimm
      4 Michał Janiszewski
      4 Karl Tomlinson
      4 Emilio Cobos Álvarez
      4 dequis
      4 Daniel Xu
      3 Pip Cet
      3 Petr Spacek
      3 Mike West
      3 Mate Antunovic
      3 Kartikaya Gupta
      3 Gabriel Ganne
      3 Ehsan Akhgari
      3 Daniel Holbert
      2 Yuxuan Shui
      2 William Cohen
      2 snf
      2 Sidharth Kshatriya
      2 Sagar Patel
      2 roquo
      2 Neven Sajko
      2 Maks Naumov
      2 gaasedelen
      2 Francis Gagné
      2 Dominic Chen
      2 Dima Kogan
      2 David Manouchehri
      2 Changhui Liu
      2 Bob131
      2 bgirard
      2 Alexander Ivanov
      1 Zack Maril
      1 Zachary Turner
      1 z
      1 Yen Chi Hsuan
      1 Yamakaky
      1 Wesley Yue
      1 Ventero
      1 Vadim Chugunov
      1 Trevor Saunders
      1 Timothy Cyrus
      1 Ted Ying
      1 TA Thanh Dinh
      1 stepshal
      1 Seo Sanghyeon
      1 Sean Stangl
      1 pipcet
      1 Petr Špaček
      1 Peter Maydell
      1 Paul Omta
      1 Patrick O'Grady
      1 Patrick Hulin
      1 orbitcowboy
      1 orbea
      1 Nick Gregory
      1 Nick Fitzgerald
      1 namibj
      1 Mozilla-GitHub-Standards
      1 Mike Pedersen
      1 Mike Hoye
      1 Mike Frysinger
      1 Michał Karczewski
      1 Michael Stahl
      1 Matthew Fernandez
      1 Marcin Ślusarz
      1 Kavinda Wewegama
      1 Jun Inoue
      1 Juan Navarro
      1 John Reiser
      1 Jesin
      1 Jeremy Roman
      1 Hubert Figuière
      1 Gabriel
      1 Franz König
      1 Francois Marier
      1 Fangrui Song
      1 ex0dus-0x
      1 detailyang
      1 deep
      1 David Turner
      1 David R. Piegdon
      1 Daniel Brooks
      1 Dakota Sanchez
      1 Cameron McCormack
      1 Bernhard Übelacker
      1 Benjamin Schubert
      1 Benjamin King
      1 Bayrashevskiy Vladimir
      1 Arturo Martín-de-Nicolás
      1 Andrew Walton
      1 Alex Pakhunov
      1 aarzilli
```

**Thank you all once again for all your efforts on rr!**

The `rd` project also has selectively ported over a number of commits that appeared _after_ rr commit `abd344288878c9b4046e0b8664927992947a46eb`: in those cases, `rd` commit log messages should provide more information.
