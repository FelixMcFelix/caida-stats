set terminal tikz standalone color size 9cm,6cm font '\scriptsize' preamble '\usepackage{microtype} \usepackage[sfdefault]{FiraSans} \usepackage{newtxsf} \usepackage[T1]{fontenc} \renewcommand*\oldstylenums[1]{{\firaoldstyle #1}} \usepackage[binary-units, per-mode=symbol]{siunitx} \sisetup{detect-all}'
set output "ca-monthly-pres.tex"

load "gnuplot-palettes/parula.pal"

set boxwidth 0.9
set style data histogram
set style histogram cluster gap 1
set style fill solid border -1
set datafile separator ","
unset colorbox

set xlabel "Month"
set ylabel "Proportion"

set yrange [0.5:1.0]
set key at 10,1

plot '../results/dirA-1.csv' u 12: xtic(1) title "Dir A (Packets)" lc palette frac 0.25, \
     '../results/dirB-1.csv' u 12 title "Dir B (Packets)" lc palette frac 0.5, \
     '../results/biDir-1.csv' u 12 title "Both (Packets)" lc palette frac 0.75