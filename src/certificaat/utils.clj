(ns certificaat.utils
  (:require [clojure.string :as str]
            [clojure.java.io :as io])
  (:import java.net.URL
           [org.slf4j LoggerFactory]
           [ch.qos.logback.classic Logger Level]))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

(defn load-url [path]
  (let [url-resource (io/file path)]
    (when (.exists url-resource)
      (URL. (slurp url-resource)))))

(defn verbose-logging []
  (let [root (LoggerFactory/getLogger (Logger/ROOT_LOGGER_NAME))]
    (.setLevel root Level/DEBUG)))
