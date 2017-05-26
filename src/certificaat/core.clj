(ns certificaat.core
  (:require [certificaat.interface.cli :refer [certificaat]])
  (:gen-class))

(defn -main
  "Certificaat entry point."
  [& args]
  (certificaat args))


