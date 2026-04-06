import { redirect } from 'next/navigation';

/**
 * /quickstart → /developers/guide/getting_started
 * Static redirect page for backward compatibility.
 */
export default function QuickstartRedirect() {
  redirect('/developers/guide/getting_started');
}
