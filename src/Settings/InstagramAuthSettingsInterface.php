<?php

namespace Drupal\social_auth_instagram\Settings;

/**
 * Defines an interface for Social Auth Instagram settings.
 */
interface InstagramAuthSettingsInterface {

  /**
   * Gets the client ID.
   *
   * @return string
   *   The client ID.
   */
  public function getClientId();

  /**
   * Gets the client secret.
   *
   * @return string
   *   The client secret.
   */
  public function getClientSecret();

}
