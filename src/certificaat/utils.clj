(ns certificaat.utils
  (:require [clojure.string :as str]))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  ;(System/exit status)
  )
