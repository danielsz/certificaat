(ns certificaat.plugins.report
  (:require [puget.printer :as puget]
            [postal.core :refer [send-message]]
            [certificaat.kung-fu :as k])
  (:import [java.time LocalDate]
           [java.net URL]))

(defn report [{{{sendmail :sendmail smtp :smtp} :email} :plugins domain :domain contact :contact :as options}]
  (let [info (k/info options)
        body (puget/render-str (puget/pretty-printer {:color-markup :html-inline :print-color true}) info)
        m {:from (str "certificaat-cron@" domain)
           :to (.getPath  (URL. contact))
           :subject (str "Certificaat run " (LocalDate/now))
           :body body}]
    (if sendmail
      (send-message m)
      (send-message smtp m))))



