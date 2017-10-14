(ns certificaat.plugins.report
  (:require [puget.printer :as puget]
            [postal.core :refer [send-message]]
            [certificaat.kung-fu :as k])
  (:import [java.time LocalDate]
           [java.net URL]))

(defn report [{{{sendmail :sendmail smtp :smtp} :email} :plugins domain :domain contact :contact :as options}]
  (let [info (k/info options)
        html (puget/render-str (puget/pretty-printer {:color-markup :html-inline :print-color true}) info)
        text (puget/render-str (puget/pretty-printer {}) info)
        m {:from (str "certificaat-cron@" domain)
           :to (.getPath  (URL. contact))
           :subject (str "Certificaat " (LocalDate/now))
           :body [:alternative
                  {:type "text/plain"
                   :content text}
                  {:type "text/html"
                   :content html}]}]
    (if sendmail
      (send-message m)
      (send-message smtp m))))



