# Readme for shared code from Beyond the Hype paper

This is example code on fake data from our Beyond The Hype paper. It provides a cost-benefit analysis for reasoning about malware detectors.

For details on the approach and when referencing use of this code please cite our paper:

  Bridges, Robert A., Sean Oesch, Miki E. Verma, Michael D. Iannacone, Kelly MT Huffer, Brian Jewell, Jeff A. Nichols et al. "Beyond the Hype: A Real-World Evaluation of the Impact and Cost of Machine Learning-Based Malware Detection." arXiv preprint arXiv:2012.09214 (2022).

@misc{bridges2022beyond,
  doi = {10.48550/ARXIV.2012.09214},
  url = {https://arxiv.org/abs/2012.09214},  
  author = {Bridges, Robert A. and Oesch, Sean and Verma, Miki E. and Iannacone, Michael D. and Huffer, Kelly M. T. and Jewell, Brian and Nichols, Jeff A. and Weber, Brian and Beaver, Justin M. and Smith, Jared M. and Scofield, Daniel and Miles, Craig and Plummer, Thomas and Daniell, Mark and Tall, Anne M.},
  title = {Beyond the Hype: A Real-World Evaluation of the Impact and Cost of Machine Learning-Based Malware Detection},  
  publisher = {arXiv},  
  year = {2022},
}


Repository contents:

- readme.md - this file!

- fake-data-table.csv
  This is a table of simulated data from two malware detectors, with randomly generated results suitable for running the cost model code as an example. It has the following columns:
  - filename - string, gives name of fake file
  - filetype - string, gives filetype/category.
  - malicious - boolean, 1 for malware, 0 if benign
  - polyglot - boolean, 1 if polyglot
  - zero_day - boolean, 1 if zero-day file
  - time_to_detect_1 - float or nan. This gives the time the first (simulated) tool alerted. nan indicates no alert.
  - time_to_detect_2 - float or nan. This gives the time the second (simulated) tool alerted. nan indicates no alert.

- code/

  - config.py - provides global variables with input parameters needed for the cost model.

  - model.py - provides the functions needed to run the cost model with examples on the fake data and three simulated detectors. Includes the complementary cost model--computes savings/costs of adding a network detector to a host detector.

  - make_plots.py - shows example plots varying parameters.

- plots/ # contents populated by ./code/make_plots.py
