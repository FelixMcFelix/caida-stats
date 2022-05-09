set terminal tikz standalone color size 9cm,6cm font '\scriptsize' preamble '\usepackage{microtype} \usepackage{libertinus} \usepackage{libertinust1math} \usepackage[binary-units, per-mode=symbol]{siunitx}\sisetup{detect-all} \newcommand{\approachshort}{OPaL} \newcommand{\Coopfw}{CoOp} \newcommand{\coopfw}{\Coopfw} \newcommand{\Indfw}{Ind} \newcommand{\indfw}{\Indfw}'
set output "ca-monthly-bytes.tex"

load "gnuplot-palettes/inferno.pal"

set boxwidth 0.9
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set datafile separator ","
unset colorbox

set xlabel "Month"
set ylabel "Proportion (Bytes)"

set yrange [0.5:1.0]
set key at 10,1

plot '../results/dirA-1.csv' u 13: xtic(1) title "Dir A" lc palette frac 0.25 fill pattern 1, \
     '../results/dirB-1.csv' u 13 title "Dir B" lc palette frac 0.5 fill pattern 2, \
     '../results/biDir-1.csv' u 13 title "Both" lc palette frac 0.75 fill pattern 7