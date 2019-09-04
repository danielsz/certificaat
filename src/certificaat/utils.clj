(ns certificaat.utils
  (:require [clojure.string :as str]
            [clojure.java.io :as io])
  (:import java.net.URL))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  ;(System/exit status)
)

(defn load-url [path]
  (let [url-resource (io/file path)]
    (when (.exists url-resource)
      (URL. (slurp url-resource)))))
