(ns tedken.core-test
  (:use [midje.sweet])
  (:require [environ.core :refer [env]]))

(defn insecure-request
  "Creates a RING request with no token"
  []
  {:method :post
   :headers []})

(defn secure-request
  "Creases a secure RING request that incoprorates the encrypted token for CSRF protection"
  [token]
  {:method :post
   :headers {"X-CSRF-Token" token}})

(defn dummy-handler
  "A dummy RING handler that always returns OK"
  [request]
  {:status 200
   :headers {}
   :body "Everything is ok!"})

(def secured-handler (wrap-csrf-token dummy-handler))

(let [secured (secure-request "foobar")
      insecure (insecure-request)]
  (facts "I can protect my requests from CSRF"
         (fact "Insecure requests are forbidden"
               (secured-handler insecure)    => (contains #{[:status 401]}))
         (fact "Secure requests are processed"
               (secured-handler secured)    => (contains #{[:status 200]}))))

(let [secret "secret"]
  (fact "I can encrypt the token"
        (secure "test") =not=> "test"
        (secure "test") => (fn [actual]
                             (= "test" (unwrap actual)))))
