(ns certificaat.tentoontenstelling
  (:require [clojure.tools.logging :as log])
  (:import [javax.swing JOptionPane]
           [java.awt GraphicsEnvironment]
           [org.shredzone.acme4j.exception AcmeException]))


(defmulti show-tos (fn [title tos] (GraphicsEnvironment/isHeadless)))
(defmethod show-tos true [title tos] (println tos))
(defmethod show-tos false [title tos] (JOptionPane/showMessageDialog nil tos title JOptionPane/INFORMATION_MESSAGE))

(defmulti confirm-dialog (fn [title message] (GraphicsEnvironment/isHeadless)))
(defmethod confirm-dialog true [title message] (do (println message)
                                                   (println "Do you accept? (Please type Yes or no)")
                                                   (let [option (read-line)]
                                                     (= "Yes" option))))
(defmethod confirm-dialog false [title message] (let [option (JOptionPane/showConfirmDialog nil message title JOptionPane/OK_CANCEL_OPTION)]
                                              (when (= option JOptionPane/CANCEL_OPTION)
                                                (throw (AcmeException. "User cancelled the operation")))))
