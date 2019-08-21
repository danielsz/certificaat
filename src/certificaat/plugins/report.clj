(ns certificaat.plugins.report
  (:require [puget.printer :as puget]
            [postal.core :refer [send-message]]
            [certificaat.utils :as utils])
  (:import [java.time LocalDate]
           [java.net URL]))

(defn report [{{{sendmail :sendmail smtp :smtp enabled :enabled} :email} :plugins domain :domain contact :contact :as options}]
  (when enabled
    (let [info (utils/info options)
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
                    (send-message smtp m)))))
