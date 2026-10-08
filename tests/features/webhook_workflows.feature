Feature: Webhook-driven workflows respect policy
  Workflows triggered by signed webhooks run tools as a service principal,
  through the same policy and audit path as direct tool calls.

  Background:
    Given the acme tenant has connected GitHub, Slack and HubSpot

  Scenario: A new GitHub issue is announced in Slack
    When GitHub sends a signed "issues" webhook for a new issue titled "Payments page 500s"
    Then Slack channel "#eng" receives "New issue: Payments page 500s"
    And the audit log chain is intact

  Scenario: A forged webhook is ignored
    When someone sends an "issues" webhook with a bad signature
    Then the hub answers 401
    And Slack receives nothing

  Scenario: A viewer cannot post to Slack
    When viewer "victor" calls "slack_post_message" on "#eng"
    Then the call is denied with "role_not_permitted"
    And the denial is in the audit log
